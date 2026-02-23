import fnmatch
import glob
import json
import logging
import os
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from urllib.parse import urljoin

import sentry_sdk
from allauth.socialaccount.models import SocialAccount, SocialApp
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.saml.views import FinishACSView, LoginView
from botocore.exceptions import ClientError, NoCredentialsError, ParamValidationError
from celery.result import AsyncResult
from config.custom_logging import BackendLogger
from config.env import env
from config.settings.social_login import (
    GITHUB_OAUTH_CALLBACK_URL,
    GOOGLE_OAUTH_CALLBACK_URL,
)
from dj_rest_auth.registration.views import SocialLoginView
from django.conf import settings as django_settings
from django.contrib.postgres.aggregates import ArrayAgg
from django.contrib.postgres.search import SearchQuery
from django.db import transaction
from django.db.models import (
    Case,
    Count,
    DecimalField,
    ExpressionWrapper,
    F,
    IntegerField,
    Max,
    Prefetch,
    Q,
    Subquery,
    Sum,
    Value,
    When,
    Window,
)
from django.db.models.functions import Coalesce, RowNumber
from django.http import HttpResponse, QueryDict
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.dateparse import parse_date
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from django_celery_beat.models import PeriodicTask
from drf_spectacular.settings import spectacular_settings
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from drf_spectacular.views import SpectacularAPIView
from drf_spectacular_jsonapi.schemas.openapi import JsonApiAutoSchema
from rest_framework import permissions, status
from rest_framework.decorators import action
from rest_framework.exceptions import (
    MethodNotAllowed,
    NotFound,
    PermissionDenied,
    ValidationError,
)
from rest_framework.generics import GenericAPIView, get_object_or_404
from rest_framework.permissions import SAFE_METHODS
from rest_framework_json_api.views import RelationshipView, Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from tasks.beat import schedule_provider_scan
from tasks.jobs.attack_paths import db_utils as attack_paths_db_utils
from tasks.jobs.export import get_s3_client
from tasks.tasks import (
    backfill_compliance_summaries_task,
    backfill_scan_resource_summaries_task,
    check_integration_connection_task,
    check_lighthouse_connection_task,
    check_lighthouse_provider_connection_task,
    check_provider_connection_task,
    delete_provider_task,
    delete_tenant_task,
    jira_integration_task,
    mute_historical_findings_task,
    perform_scan_task,
    refresh_lighthouse_provider_models_task,
)

from api.attack_paths import database as graph_database
from api.attack_paths import get_queries_for_provider, get_query_by_id
from api.attack_paths import views_helpers as attack_paths_views_helpers
from api.base_views import BaseRLSViewSet, BaseTenantViewset, BaseUserViewset
from api.compliance import (
    PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE,
    get_compliance_frameworks,
)
from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.exceptions import (
    TaskFailedException,
    UpstreamAccessDeniedError,
    UpstreamAuthenticationError,
    UpstreamInternalError,
    UpstreamServiceUnavailableError,
)
from api.filters import (
    AttackPathsScanFilter,
    AttackSurfaceOverviewFilter,
    CategoryOverviewFilter,
    ComplianceOverviewFilter,
    ComplianceWatchlistFilter,
    CustomDjangoFilterBackend,
    DailySeveritySummaryFilter,
    FindingFilter,
    IntegrationFilter,
    IntegrationJiraFindingsFilter,
    InvitationFilter,
    LatestFindingFilter,
    LatestResourceFilter,
    LighthouseProviderConfigFilter,
    LighthouseProviderModelsFilter,
    MembershipFilter,
    MuteRuleFilter,
    ProcessorFilter,
    ProviderFilter,
    ProviderGroupFilter,
    ProviderSecretFilter,
    ResourceFilter,
    ResourceGroupOverviewFilter,
    RoleFilter,
    ScanFilter,
    ScanSummaryFilter,
    ScanSummarySeverityFilter,
    TaskFilter,
    TenantApiKeyFilter,
    TenantFilter,
    ThreatScoreSnapshotFilter,
    UserFilter,
)
from api.models import (
    AttackPathsScan,
    AttackSurfaceOverview,
    ComplianceOverviewSummary,
    ComplianceRequirementOverview,
    DailySeveritySummary,
    Finding,
    Integration,
    Invitation,
    LighthouseConfiguration,
    LighthouseProviderConfiguration,
    LighthouseProviderModels,
    LighthouseTenantConfiguration,
    Membership,
    MuteRule,
    Processor,
    Provider,
    ProviderComplianceScore,
    ProviderGroup,
    ProviderGroupMembership,
    ProviderSecret,
    Resource,
    ResourceFindingMapping,
    ResourceScanSummary,
    ResourceTag,
    Role,
    RoleProviderGroupRelationship,
    SAMLConfiguration,
    SAMLDomainIndex,
    SAMLToken,
    Scan,
    ScanCategorySummary,
    ScanGroupSummary,
    ScanSummary,
    SeverityChoices,
    StateChoices,
    Task,
    TenantAPIKey,
    TenantComplianceSummary,
    ThreatScoreSnapshot,
    User,
    UserRoleRelationship,
)
from api.pagination import ComplianceOverviewPagination
from api.rbac.permissions import Permissions, get_providers, get_role
from api.rls import Tenant
from api.utils import (
    CustomOAuth2Client,
    get_findings_metadata_no_aggregations,
    initialize_prowler_provider,
    validate_invitation,
)
from api.uuid_utils import datetime_to_uuid7, uuid7_start
from api.v1.mixins import DisablePaginationMixin, PaginateByPkMixin, TaskManagementMixin
from api.v1.serializers import (
    AttackPathsQueryResultSerializer,
    AttackPathsQueryRunRequestSerializer,
    AttackPathsQuerySerializer,
    AttackPathsScanSerializer,
    AttackSurfaceOverviewSerializer,
    CategoryOverviewSerializer,
    ComplianceOverviewAttributesSerializer,
    ComplianceOverviewDetailSerializer,
    ComplianceOverviewDetailThreatscoreSerializer,
    ComplianceOverviewMetadataSerializer,
    ComplianceOverviewSerializer,
    ComplianceWatchlistOverviewSerializer,
    FindingDynamicFilterSerializer,
    FindingMetadataSerializer,
    FindingSerializer,
    FindingsSeverityOverTimeSerializer,
    IntegrationCreateSerializer,
    IntegrationJiraDispatchSerializer,
    IntegrationSerializer,
    IntegrationUpdateSerializer,
    InvitationAcceptSerializer,
    InvitationCreateSerializer,
    InvitationSerializer,
    InvitationUpdateSerializer,
    LighthouseConfigCreateSerializer,
    LighthouseConfigSerializer,
    LighthouseConfigUpdateSerializer,
    LighthouseProviderConfigCreateSerializer,
    LighthouseProviderConfigSerializer,
    LighthouseProviderConfigUpdateSerializer,
    LighthouseProviderModelsSerializer,
    LighthouseTenantConfigSerializer,
    LighthouseTenantConfigUpdateSerializer,
    MembershipSerializer,
    MuteRuleCreateSerializer,
    MuteRuleSerializer,
    MuteRuleUpdateSerializer,
    OverviewFindingSerializer,
    OverviewProviderCountSerializer,
    OverviewProviderSerializer,
    OverviewRegionSerializer,
    OverviewServiceSerializer,
    OverviewSeveritySerializer,
    ProcessorCreateSerializer,
    ProcessorSerializer,
    ProcessorUpdateSerializer,
    ProviderCreateSerializer,
    ProviderGroupCreateSerializer,
    ProviderGroupMembershipSerializer,
    ProviderGroupSerializer,
    ProviderGroupUpdateSerializer,
    ProviderSecretCreateSerializer,
    ProviderSecretSerializer,
    ProviderSecretUpdateSerializer,
    ProviderSerializer,
    ProviderUpdateSerializer,
    ResourceEventSerializer,
    ResourceGroupOverviewSerializer,
    ResourceMetadataSerializer,
    ResourceSerializer,
    RoleCreateSerializer,
    RoleProviderGroupRelationshipSerializer,
    RoleSerializer,
    RoleUpdateSerializer,
    SAMLConfigurationSerializer,
    SamlInitiateSerializer,
    ScanComplianceReportSerializer,
    ScanCreateSerializer,
    ScanReportSerializer,
    ScanSerializer,
    ScanUpdateSerializer,
    ScheduleDailyCreateSerializer,
    TaskSerializer,
    TenantApiKeyCreateSerializer,
    TenantApiKeySerializer,
    TenantApiKeyUpdateSerializer,
    TenantSerializer,
    ThreatScoreSnapshotSerializer,
    TokenRefreshSerializer,
    TokenSerializer,
    TokenSocialLoginSerializer,
    TokenSwitchTenantSerializer,
    UserCreateSerializer,
    UserRoleRelationshipSerializer,
    UserSerializer,
    UserUpdateSerializer,
)
from prowler.providers.aws.exceptions.exceptions import (
    AWSAssumeRoleError,
    AWSCredentialsError,
)
from prowler.providers.aws.lib.cloudtrail_timeline.cloudtrail_timeline import (
    CloudTrailTimeline,
)

logger = logging.getLogger(BackendLogger.API)

CACHE_DECORATOR = cache_control(
    max_age=django_settings.CACHE_MAX_AGE,
    stale_while_revalidate=django_settings.CACHE_STALE_WHILE_REVALIDATE,
)


class RelationshipViewSchema(JsonApiAutoSchema):
    def _resolve_path_parameters(self, _path_variables):
        return []


@extend_schema(
    tags=["Token"],
    summary="Obtain a token",
    description="Obtain a token by providing valid credentials and an optional tenant ID.",
)
class CustomTokenObtainView(GenericAPIView):
    throttle_scope = "token-obtain"

    resource_name = "tokens"
    serializer_class = TokenSerializer
    http_method_names = ["post"]

    def post(self, request):
        serializer = TokenSerializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(
            data={"type": "tokens", "attributes": serializer.validated_data},
            status=status.HTTP_200_OK,
        )


@extend_schema(
    tags=["Token"],
    summary="Refresh a token",
    description="Refresh an access token by providing a valid refresh token. Former refresh tokens are invalidated "
    "when a new one is issued.",
)
class CustomTokenRefreshView(GenericAPIView):
    resource_name = "tokens-refresh"
    serializer_class = TokenRefreshSerializer
    http_method_names = ["post"]

    def post(self, request):
        serializer = TokenRefreshSerializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(
            data={"type": "tokens-refresh", "attributes": serializer.validated_data},
            status=status.HTTP_200_OK,
        )


@extend_schema(
    tags=["Token"],
    summary="Switch tenant using a valid tenant ID",
    description="Switch tenant by providing a valid tenant ID. The authenticated user must belong to the tenant.",
)
class CustomTokenSwitchTenantView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    resource_name = "tokens-switch-tenant"
    serializer_class = TokenSwitchTenantSerializer
    http_method_names = ["post"]

    def post(self, request):
        serializer = TokenSwitchTenantSerializer(
            data=request.data, context={"request": request}
        )

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(
            data={
                "type": "tokens-switch-tenant",
                "attributes": serializer.validated_data,
            },
            status=status.HTTP_200_OK,
        )


@extend_schema(exclude=True)
class SchemaView(SpectacularAPIView):
    serializer_class = None

    def get(self, request, *args, **kwargs):
        spectacular_settings.TITLE = "Prowler API"
        spectacular_settings.VERSION = "1.20.0"
        spectacular_settings.DESCRIPTION = (
            "Prowler API specification.\n\nThis file is auto-generated."
        )
        spectacular_settings.TAGS = [
            {"name": "User", "description": "Endpoints for managing user accounts."},
            {
                "name": "Token",
                "description": "Endpoints for token management, including obtaining a new token and "
                "refreshing an existing token for authentication purposes.",
            },
            {
                "name": "Tenant",
                "description": "Endpoints for managing tenants, along with their memberships.",
            },
            {
                "name": "Invitation",
                "description": "Endpoints for tenant invitations management, allowing retrieval and filtering of "
                "invitations, creating new invitations, accepting and revoking them.",
            },
            {
                "name": "Role",
                "description": "Endpoints for managing RBAC roles within tenants, allowing creation, retrieval, "
                "updating, and deletion of role configurations and permissions.",
            },
            {
                "name": "Provider",
                "description": "Endpoints for managing providers (AWS, GCP, Azure, etc...).",
            },
            {
                "name": "Provider Group",
                "description": "Endpoints for managing provider groups.",
            },
            {
                "name": "Task",
                "description": "Endpoints for task management, allowing retrieval of task status and "
                "revoking tasks that have not started.",
            },
            {
                "name": "Scan",
                "description": "Endpoints for triggering manual scans and viewing scan results.",
            },
            {
                "name": "Attack Paths",
                "description": "Endpoints for Attack Paths scan status and executing Attack Paths queries.",
            },
            {
                "name": "Schedule",
                "description": "Endpoints for managing scan schedules, allowing configuration of automated "
                "scans with different scheduling options.",
            },
            {
                "name": "Resource",
                "description": "Endpoints for managing resources discovered by scans, allowing "
                "retrieval and filtering of resource information.",
            },
            {
                "name": "Finding",
                "description": "Endpoints for managing findings, allowing retrieval and filtering of "
                "findings that result from scans.",
            },
            {
                "name": "Processor",
                "description": "Endpoints for managing post-processors used to process Prowler findings, including "
                "registration, configuration, and deletion of post-processing actions.",
            },
            {
                "name": "Compliance Overview",
                "description": "Endpoints for checking the compliance overview, allowing filtering by scan, provider or"
                " compliance framework ID.",
            },
            {
                "name": "Overview",
                "description": "Endpoints for retrieving aggregated summaries of resources from the system.",
            },
            {
                "name": "Integration",
                "description": "Endpoints for managing third-party integrations, including registration, configuration,"
                " retrieval, and deletion of integrations such as S3, JIRA, or other services.",
            },
            {
                "name": "Lighthouse AI",
                "description": "Endpoints for managing Lighthouse AI configurations, including creation, retrieval, "
                "updating, and deletion of configurations such as OpenAI keys, models, and business "
                "context.",
            },
            {
                "name": "SAML",
                "description": "Endpoints for Single Sign-On authentication management via SAML for seamless user "
                "authentication.",
            },
            {
                "name": "API Keys",
                "description": "Endpoints for API keys management. These can be used as an alternative to JWT "
                "authorization.",
            },
            {
                "name": "Mute Rules",
                "description": "Endpoints for simple mute rules management. These can be used as an alternative to the"
                " Mutelist Processor if you need to mute specific findings across your tenant with a "
                "specific reason.",
            },
        ]
        return super().get(request, *args, **kwargs)


@extend_schema(exclude=True)
class GoogleSocialLoginView(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    client_class = CustomOAuth2Client
    callback_url = GOOGLE_OAUTH_CALLBACK_URL

    def get_response(self):
        original_response = super().get_response()

        if self.user and self.user.is_authenticated:
            serializer = TokenSocialLoginSerializer(data={"email": self.user.email})
            try:
                serializer.is_valid(raise_exception=True)
            except TokenError as e:
                raise InvalidToken(e.args[0])
            return Response(
                data={
                    "type": "google-social-tokens",
                    "attributes": serializer.validated_data,
                },
                status=status.HTTP_200_OK,
            )
        return original_response


@extend_schema(exclude=True)
class GithubSocialLoginView(SocialLoginView):
    adapter_class = GitHubOAuth2Adapter
    client_class = CustomOAuth2Client
    callback_url = GITHUB_OAUTH_CALLBACK_URL

    def get_response(self):
        original_response = super().get_response()

        if self.user and self.user.is_authenticated:
            serializer = TokenSocialLoginSerializer(data={"email": self.user.email})

            try:
                serializer.is_valid(raise_exception=True)
            except TokenError as e:
                raise InvalidToken(e.args[0])

            return Response(
                data={
                    "type": "github-social-tokens",
                    "attributes": serializer.validated_data,
                },
                status=status.HTTP_200_OK,
            )
        return original_response


@extend_schema(exclude=True)
class SAMLTokenValidateView(GenericAPIView):
    resource_name = "tokens"
    http_method_names = ["post"]

    def post(self, request):
        token_id = request.query_params.get("id", "invalid")
        try:
            saml_token = SAMLToken.objects.using(MainRouter.admin_db).get(id=token_id)
        except SAMLToken.DoesNotExist:
            return Response({"detail": "Invalid token ID."}, status=404)

        if saml_token.is_expired():
            return Response({"detail": "Token expired."}, status=400)

        token_data = saml_token.token
        # Currently we don't store the tokens in the database, so we delete the token after use
        saml_token.delete()

        return Response(token_data, status=200)


@extend_schema(exclude=True)
class CustomSAMLLoginView(LoginView):
    def dispatch(self, request, *args, **kwargs):
        """
        Convert GET requests to POST to bypass allauth's confirmation screen.

        Why this is necessary:
        - django-allauth requires POST for social logins to prevent open redirect attacks
        - SAML login links typically use GET requests (e.g., <a href="...">)
        - This conversion allows seamless login without user-facing confirmation

        Security considerations:
        1. Preserves CSRF protection: Original POST handling remains intact
        2. Avoids global SOCIALACCOUNT_LOGIN_ON_GET=True which would:
           - Enable GET logins for ALL providers (security risk)
           - Potentially expose open redirect vulnerabilities
        3. SAML payloads remain signed/encrypted regardless of HTTP method
        4. No sensitive parameters are exposed in URLs (copied to POST body)

        This approach maintains security while providing better UX.
        """
        if request.method == "GET":
            # Convert GET to POST while preserving parameters
            request.method = "POST"
        return super().dispatch(request, *args, **kwargs)


@extend_schema(exclude=True)
class SAMLInitiateAPIView(GenericAPIView):
    serializer_class = SamlInitiateSerializer
    permission_classes = []

    def post(self, request, *args, **kwargs):
        # Validate the input payload and extract the domain
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email_domain"]
        domain = email.split("@", 1)[-1].lower()

        # Retrieve the SAML configuration for the given email domain
        try:
            check = SAMLDomainIndex.objects.get(email_domain=domain)
            with rls_transaction(str(check.tenant_id)):
                config = SAMLConfiguration.objects.get(tenant_id=str(check.tenant_id))
        except (SAMLDomainIndex.DoesNotExist, SAMLConfiguration.DoesNotExist):
            return Response(
                {"detail": "Unauthorized domain."}, status=status.HTTP_403_FORBIDDEN
            )

        # Check certificates are not empty (TODO: Validate certificates)
        # saml_public_cert = os.getenv("SAML_PUBLIC_CERT", "").strip()
        # saml_private_key = os.getenv("SAML_PRIVATE_KEY", "").strip()

        # if not saml_public_cert or not saml_private_key:
        #     return Response(
        #         {"detail": "SAML configuration is invalid: missing certificates."},
        #         status=status.HTTP_403_FORBIDDEN,
        #     )

        # Build the SAML login URL using the configured API host
        api_host = os.getenv("API_BASE_URL")
        login_path = reverse(
            "saml_login", kwargs={"organization_slug": config.email_domain}
        )
        login_url = urljoin(api_host, login_path)

        return redirect(login_url)


@extend_schema_view(
    list=extend_schema(
        tags=["SAML"],
        summary="List all SSO configurations",
        description="Returns all the SAML-based SSO configurations associated with the current tenant.",
    ),
    retrieve=extend_schema(
        tags=["SAML"],
        summary="Retrieve SSO configuration details",
        description="Returns the details of a specific SAML configuration belonging to the current tenant.",
    ),
    create=extend_schema(
        tags=["SAML"],
        summary="Create the SSO configuration",
        description="Creates a new SAML SSO configuration for the current tenant, including email domain and metadata XML.",
    ),
    partial_update=extend_schema(
        tags=["SAML"],
        summary="Update the SSO configuration",
        description="Partially updates an existing SAML SSO configuration. Supports changes to email domain and metadata XML.",
    ),
    destroy=extend_schema(
        tags=["SAML"],
        summary="Delete the SSO configuration",
        description="Deletes an existing SAML SSO configuration associated with the current tenant.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="retrieve")
@method_decorator(CACHE_DECORATOR, name="list")
class SAMLConfigurationViewSet(BaseRLSViewSet):
    """
    ViewSet for managing SAML SSO configurations per tenant.

    This endpoint allows authorized users to perform CRUD operations on SAMLConfiguration,
    which define how a tenant integrates with an external SAML Identity Provider (IdP).

    Typical use cases include:
        - Listing all existing configurations for auditing or UI display.
        - Retrieving a single configuration to show setup details.
        - Creating or updating a configuration to onboard or modify SAML integration.
        - Deleting a configuration when deactivating SAML for a tenant.
    """

    serializer_class = SAMLConfigurationSerializer
    required_permissions = [Permissions.MANAGE_INTEGRATIONS]
    queryset = SAMLConfiguration.objects.all()

    def get_queryset(self):
        # If called during schema generation, return an empty queryset
        if getattr(self, "swagger_fake_view", False):
            return SAMLConfiguration.objects.none()
        return SAMLConfiguration.objects.filter(tenant=self.request.tenant_id)


class TenantFinishACSView(FinishACSView):
    def _rollback_saml_user(self, request):
        """Helper function to rollback SAML user if it was just created and validation fails"""
        saml_user_id = request.session.get("saml_user_created")
        if saml_user_id:
            User.objects.using(MainRouter.admin_db).filter(id=saml_user_id).delete()
            request.session.pop("saml_user_created", None)

    def dispatch(self, request, organization_slug):
        try:
            super().dispatch(request, organization_slug)
        except Exception as e:
            logger.error(f"SAML dispatch failed: {e}")
            self._rollback_saml_user(request)
            callback_url = env.str("AUTH_URL")
            return redirect(f"{callback_url}?sso_saml_failed=true")

        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            self._rollback_saml_user(request)
            callback_url = env.str("AUTH_URL")
            return redirect(f"{callback_url}?sso_saml_failed=true")

        # Defensive check to avoid edge case failures due to inconsistent or incomplete data in the database
        # This handles scenarios like partially deleted or missing related objects
        try:
            check = SAMLDomainIndex.objects.get(email_domain=organization_slug)
            with rls_transaction(str(check.tenant_id)):
                SAMLConfiguration.objects.get(tenant_id=str(check.tenant_id))
            social_app = SocialApp.objects.get(
                provider="saml", client_id=organization_slug
            )
            user_id = User.objects.get(email=str(user)).id
            social_account = SocialAccount.objects.get(
                user=str(user_id), provider=social_app.provider_id
            )
        except (
            SAMLDomainIndex.DoesNotExist,
            SAMLConfiguration.DoesNotExist,
            SocialApp.DoesNotExist,
            SocialAccount.DoesNotExist,
            User.DoesNotExist,
        ) as e:
            logger.error(f"SAML user is not authenticated: {e}")
            self._rollback_saml_user(request)
            callback_url = env.str("AUTH_URL")
            return redirect(f"{callback_url}?sso_saml_failed=true")

        extra = social_account.extra_data
        user.first_name = (
            extra.get("firstName", [""])[0] if extra.get("firstName") else ""
        )
        user.last_name = extra.get("lastName", [""])[0] if extra.get("lastName") else ""
        user.company_name = (
            extra.get("organization", [""])[0] if extra.get("organization") else ""
        )
        user.name = f"{user.first_name} {user.last_name}".strip()
        if user.name == "":
            user.name = "N/A"
        user.save()

        email_domain = user.email.split("@")[-1]
        tenant = (
            SAMLConfiguration.objects.using(MainRouter.admin_db)
            .get(email_domain=email_domain)
            .tenant
        )

        role_name = (
            extra.get("userType", ["no_permissions"])[0].strip()
            if extra.get("userType")
            else "no_permissions"
        )
        role = (
            Role.objects.using(MainRouter.admin_db)
            .filter(name=role_name, tenant=tenant)
            .first()
        )

        # Only skip mapping if it would remove the last MANAGE_ACCOUNT user
        remaining_manage_account_users = (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(role__manage_account=True, tenant_id=tenant.id)
            .exclude(user_id=user_id)
            .values("user")
            .distinct()
            .count()
        )
        user_has_manage_account = (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(role__manage_account=True, tenant_id=tenant.id, user_id=user_id)
            .exists()
        )
        role_manage_account = role.manage_account if role else False
        would_remove_last_manage_account = (
            user_has_manage_account
            and remaining_manage_account_users == 0
            and not role_manage_account
        )

        if not would_remove_last_manage_account:
            if role is None:
                role = Role.objects.using(MainRouter.admin_db).create(
                    name=role_name,
                    tenant=tenant,
                    manage_users=False,
                    manage_account=False,
                    manage_billing=False,
                    manage_providers=False,
                    manage_integrations=False,
                    manage_scans=False,
                    unlimited_visibility=False,
                )
            UserRoleRelationship.objects.using(MainRouter.admin_db).filter(
                user=user,
                tenant_id=tenant.id,
            ).delete()
            UserRoleRelationship.objects.using(MainRouter.admin_db).create(
                user=user,
                role=role,
                tenant_id=tenant.id,
            )
        membership, _ = Membership.objects.using(MainRouter.admin_db).get_or_create(
            user=user,
            tenant=tenant,
            defaults={
                "user": user,
                "tenant": tenant,
                "role": Membership.RoleChoices.MEMBER,
            },
        )

        serializer = TokenSocialLoginSerializer(
            data={"email": user.email, "tenant_id": str(tenant.id)}
        )
        serializer.is_valid(raise_exception=True)

        token_data = serializer.validated_data
        saml_token = SAMLToken.objects.using(MainRouter.admin_db).create(
            token=token_data, user=user
        )
        callback_url = env.str("SAML_SSO_CALLBACK_URL")
        redirect_url = f"{callback_url}?id={saml_token.id}"
        request.session.pop("saml_user_created", None)

        return redirect(redirect_url)


@extend_schema_view(
    list=extend_schema(
        tags=["User"],
        summary="List all users",
        description="Retrieve a list of all users with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        tags=["User"],
        summary="Retrieve a user's information",
        description="Fetch detailed information about an authenticated user.",
    ),
    create=extend_schema(
        tags=["User"],
        summary="Register a new user",
        description="Create a new user account by providing the necessary registration details.",
    ),
    partial_update=extend_schema(
        tags=["User"],
        summary="Update user information",
        description="Partially update information about a user.",
    ),
    destroy=extend_schema(
        tags=["User"],
        summary="Delete the user account",
        description="Remove the current user account from the system.",
    ),
    me=extend_schema(
        tags=["User"],
        summary="Retrieve the current user's information",
        description="Fetch detailed information about the authenticated user.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
class UserViewSet(BaseUserViewset):
    serializer_class = UserSerializer
    http_method_names = ["get", "post", "patch", "delete"]
    filterset_class = UserFilter
    ordering = ["-date_joined"]
    ordering_fields = ["name", "email", "company_name", "date_joined", "is_active"]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_USERS]

    def set_required_permissions(self):
        """
        Returns the required permissions based on the request method.
        """
        if self.action == "me":
            # No permissions required for me request
            self.required_permissions = []
        else:
            # Require permission for the rest of the requests
            self.required_permissions = [Permissions.MANAGE_USERS]

    def get_queryset(self):
        # If called during schema generation, return an empty queryset
        if getattr(self, "swagger_fake_view", False):
            return User.objects.none()

        queryset = (
            User.objects.filter(membership__tenant__id=self.request.tenant_id)
            if hasattr(self.request, "tenant_id")
            else User.objects.all()
        )

        return queryset.prefetch_related("memberships", "roles")

    def get_permissions(self):
        if self.action == "create":
            permission_classes = [permissions.AllowAny]
        else:
            permission_classes = self.permission_classes
        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        if self.action == "create":
            return UserCreateSerializer
        elif self.action == "partial_update":
            return UserUpdateSerializer
        else:
            return UserSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        if self.request.user.is_authenticated:
            context["role"] = get_role(self.request.user)
        return context

    @action(detail=False, methods=["get"], url_name="me")
    def me(self, request):
        user = self.request.user
        serializer = UserSerializer(user, context=self.get_serializer_context())
        return Response(
            data=serializer.data,
            status=status.HTTP_200_OK,
        )

    def destroy(self, request, *args, **kwargs):
        if kwargs["pk"] != str(self.request.user.id):
            raise ValidationError("Only the current user can be deleted.")

        user = self.get_object()
        user.delete(using=MainRouter.admin_db)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="invitation_token",
                description="Optional invitation code for joining an existing tenant.",
                required=False,
                type={"type": "string", "example": "F3NMFPNDZHR4Z9"},
                location=OpenApiParameter.QUERY,
            ),
        ]
    )
    def create(self, request, *args, **kwargs):
        invitation_token = request.query_params.get("invitation_token", None)
        invitation = None

        serializer = self.get_serializer(
            data=request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)

        if invitation_token:
            invitation = validate_invitation(
                invitation_token, serializer.validated_data["email"]
            )

        # Proceed with creating the user and membership
        user = User.objects.db_manager(MainRouter.admin_db).create_user(
            **serializer.validated_data
        )
        tenant = (
            invitation.tenant
            if invitation_token
            else Tenant.objects.using(MainRouter.admin_db).create(
                name=f"{user.email.split('@')[0]} default tenant"
            )
        )
        role = (
            Membership.RoleChoices.MEMBER
            if invitation_token
            else Membership.RoleChoices.OWNER
        )
        Membership.objects.using(MainRouter.admin_db).create(
            user=user, tenant=tenant, role=role
        )
        if invitation:
            user_role = []
            for role in invitation.roles.all():
                user_role.append(
                    UserRoleRelationship.objects.using(MainRouter.admin_db).create(
                        user=user, role=role, tenant=invitation.tenant
                    )
                )
            invitation.state = Invitation.State.ACCEPTED
            invitation.save(using=MainRouter.admin_db)
        else:
            role = Role.objects.using(MainRouter.admin_db).create(
                name="admin",
                tenant_id=tenant.id,
                manage_users=True,
                manage_account=True,
                manage_billing=True,
                manage_providers=True,
                manage_integrations=True,
                manage_scans=True,
                unlimited_visibility=True,
            )
            UserRoleRelationship.objects.using(MainRouter.admin_db).create(
                user=user,
                role=role,
                tenant_id=tenant.id,
            )
        return Response(data=UserSerializer(user).data, status=status.HTTP_201_CREATED)


@extend_schema_view(
    create=extend_schema(
        tags=["User"],
        summary="Create a new user-roles relationship",
        description="Add a new user-roles relationship to the system by providing the required user-roles details.",
        responses={
            204: OpenApiResponse(description="Relationship created successfully"),
            400: OpenApiResponse(
                description="Bad request (e.g., relationship already exists)"
            ),
        },
    ),
    partial_update=extend_schema(
        tags=["User"],
        summary="Partially update a user-roles relationship",
        description=(
            "Update the user-roles relationship information without affecting other fields. "
            "If the update would remove MANAGE_ACCOUNT from the last remaining user in the "
            "tenant, the API rejects the request with a 400 response."
        ),
        responses={
            204: OpenApiResponse(
                response=None, description="Relationship updated successfully"
            )
        },
    ),
    destroy=extend_schema(
        tags=["User"],
        summary="Delete a user-roles relationship",
        description=(
            "Remove the user-roles relationship from the system by their ID. If removing "
            "MANAGE_ACCOUNT would take it away from the last remaining user in the tenant, "
            "the API rejects the request with a 400 response. Users also cannot delete their "
            "own role assignments; attempting to do so returns a 400 response."
        ),
        responses={
            204: OpenApiResponse(
                response=None, description="Relationship deleted successfully"
            )
        },
    ),
)
class UserRoleRelationshipView(RelationshipView, BaseRLSViewSet):
    queryset = User.objects.all()
    serializer_class = UserRoleRelationshipSerializer
    resource_name = "roles"
    http_method_names = ["post", "patch", "delete"]
    schema = RelationshipViewSchema()
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_ACCOUNT]

    def get_queryset(self):
        return User.objects.filter(membership__tenant__id=self.request.tenant_id)

    def destroy(self, request, *args, **kwargs):
        """
        Prevent deleting role relationships if it would leave the tenant with no
        users having MANAGE_ACCOUNT. Supports deleting specific roles via JSON:API
        relationship payload or clearing all roles for the user when no payload.
        """
        user = self.get_object()
        # Disallow deleting own roles
        if str(user.id) == str(request.user.id):
            return Response(
                data={
                    "detail": "Users cannot delete the relationship with their role."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        tenant_id = self.request.tenant_id
        payload = request.data if isinstance(request.data, dict) else None

        # If a user has more than one role, we will delete the relationship with the roles in the payload
        data = payload.get("data") if payload else None
        if data:
            try:
                role_ids = [item["id"] for item in data]
            except KeyError:
                role_ids = []
            roles_to_remove = Role.objects.filter(id__in=role_ids, tenant_id=tenant_id)
        else:
            roles_to_remove = user.roles.filter(tenant_id=tenant_id)

        UserRoleRelationship.objects.filter(
            user=user,
            tenant_id=tenant_id,
            role_id__in=roles_to_remove.values_list("id", flat=True),
        ).delete()

        return Response(status=status.HTTP_204_NO_CONTENT)

    def create(self, request, *args, **kwargs):
        user = self.get_object()

        role_ids = [item["id"] for item in request.data]
        existing_relationships = UserRoleRelationship.objects.filter(
            user=user, role_id__in=role_ids
        )

        if existing_relationships.exists():
            return Response(
                {"detail": "One or more roles are already associated with the user."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = self.get_serializer(
            data={"roles": request.data},
            context={
                "user": user,
                "tenant_id": self.request.tenant_id,
                "request": request,
            },
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)

    def partial_update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(
            instance=user,
            data={"roles": request.data},
            context={"tenant_id": self.request.tenant_id, "request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    list=extend_schema(
        tags=["Tenant"],
        summary="List all tenants",
        description="Retrieve a list of all tenants with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        tags=["Tenant"],
        summary="Retrieve data from a tenant",
        description="Fetch detailed information about a specific tenant by their ID.",
    ),
    create=extend_schema(
        tags=["Tenant"],
        summary="Create a new tenant",
        description="Add a new tenant to the system by providing the required tenant details.",
    ),
    partial_update=extend_schema(
        tags=["Tenant"],
        summary="Partially update a tenant",
        description="Update certain fields of an existing tenant's information without affecting other fields.",
    ),
    destroy=extend_schema(
        tags=["Tenant"],
        summary="Delete a tenant",
        description="Remove a tenant from the system by their ID.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class TenantViewSet(BaseTenantViewset):
    queryset = Tenant.objects.all()
    serializer_class = TenantSerializer
    http_method_names = ["get", "post", "patch", "delete"]
    filterset_class = TenantFilter
    search_fields = ["name"]
    ordering = ["-inserted_at"]
    ordering_fields = ["name", "inserted_at", "updated_at"]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_ACCOUNT]

    def get_queryset(self):
        queryset = Tenant.objects.filter(membership__user=self.request.user)
        return queryset.prefetch_related("memberships")

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tenant = serializer.save()
        Membership.objects.create(
            user=self.request.user, tenant=tenant, role=Membership.RoleChoices.OWNER
        )
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        # This will perform validation and raise a 404 if the tenant does not exist
        tenant_id = kwargs.get("pk")
        get_object_or_404(Tenant, id=tenant_id)

        with transaction.atomic():
            # Delete memberships
            Membership.objects.using(MainRouter.admin_db).filter(
                tenant_id=tenant_id
            ).delete()

            # Delete users without memberships
            User.objects.using(MainRouter.admin_db).filter(
                membership__isnull=True
            ).delete()
        # Delete tenant in batches
        delete_tenant_task.apply_async(kwargs={"tenant_id": tenant_id})
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    list=extend_schema(
        tags=["User"],
        summary="List user memberships",
        description="Retrieve a list of all user memberships with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        tags=["User"],
        summary="Retrieve membership data from the user",
        description="Fetch detailed information about a specific user membership by their ID.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
class MembershipViewSet(BaseTenantViewset):
    http_method_names = ["get"]
    serializer_class = MembershipSerializer
    queryset = Membership.objects.all()
    filterset_class = MembershipFilter
    ordering = ["date_joined"]
    ordering_fields = [
        "tenant",
        "role",
        "date_joined",
    ]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_ACCOUNT]

    def get_queryset(self):
        user = self.request.user
        queryset = Membership.objects.filter(user_id=user.id)
        return queryset.select_related("user", "tenant")


@extend_schema_view(
    list=extend_schema(
        summary="List tenant memberships",
        description="List the membership details of users in a tenant you are a part of.",
        tags=["Tenant"],
        parameters=[
            OpenApiParameter(
                name="tenant_pk",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.PATH,
                description="Tenant ID",
            ),
        ],
    ),
    destroy=extend_schema(
        summary="Delete tenant memberships",
        description="Delete the membership details of users in a tenant. You need to be one of the owners to delete a "
        "membership that is not yours. If you are the last owner of a tenant, you cannot delete your own "
        "membership.",
        tags=["Tenant"],
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
class TenantMembersViewSet(BaseTenantViewset):
    http_method_names = ["get", "delete"]
    serializer_class = MembershipSerializer
    queryset = Membership.objects.none()
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_ACCOUNT]

    def get_queryset(self):
        tenant = self.get_tenant()
        requesting_membership = self.get_requesting_membership(tenant)

        if requesting_membership.role == Membership.RoleChoices.OWNER:
            return Membership.objects.filter(tenant=tenant)
        else:
            return Membership.objects.filter(tenant=tenant, user=self.request.user)

    def get_tenant(self):
        tenant_id = self.kwargs.get("tenant_pk")
        tenant = get_object_or_404(Tenant, id=tenant_id)
        return tenant

    def get_requesting_membership(self, tenant):
        try:
            membership = Membership.objects.get(user=self.request.user, tenant=tenant)
        except Membership.DoesNotExist:
            raise NotFound("Membership does not exist.")
        return membership

    @extend_schema(exclude=True)
    def retrieve(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="GET")

    def destroy(self, request, *args, **kwargs):
        tenant = self.get_tenant()
        membership_to_delete = get_object_or_404(
            Membership, tenant=tenant, id=kwargs.get("pk")
        )
        requesting_membership = self.get_requesting_membership(tenant)

        if requesting_membership.role == Membership.RoleChoices.OWNER:
            if membership_to_delete.user == request.user:
                # Check if the user is the last owner
                other_owners = Membership.objects.filter(
                    tenant=tenant, role=Membership.RoleChoices.OWNER
                ).exclude(user=request.user)
                if not other_owners.exists():
                    raise PermissionDenied(
                        "You cannot delete your own membership as the last owner."
                    )
        else:
            if membership_to_delete.user != request.user:
                raise PermissionDenied(
                    "You do not have permission to delete this membership."
                )

        membership_to_delete.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(tags=["Provider Group"])
@extend_schema_view(
    list=extend_schema(
        summary="List all provider groups",
        description="Retrieve a list of all provider groups with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        summary="Retrieve data from a provider group",
        description="Fetch detailed information about a specific provider group by their ID.",
    ),
    create=extend_schema(
        summary="Create a new provider group",
        description="Add a new provider group to the system by providing the required provider group details.",
    ),
    partial_update=extend_schema(
        summary="Partially update a provider group",
        description="Update certain fields of an existing provider group's information without affecting other fields.",
        request=ProviderGroupUpdateSerializer,
        responses={200: ProviderGroupSerializer},
    ),
    destroy=extend_schema(
        summary="Delete a provider group",
        description="Remove a provider group from the system by their ID.",
    ),
    update=extend_schema(exclude=True),
)
class ProviderGroupViewSet(BaseRLSViewSet):
    queryset = ProviderGroup.objects.all()
    serializer_class = ProviderGroupSerializer
    filterset_class = ProviderGroupFilter
    http_method_names = ["get", "post", "patch", "delete"]
    ordering = ["inserted_at"]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_PROVIDERS]

    def set_required_permissions(self):
        """
        Returns the required permissions based on the request method.
        """
        if self.request.method in SAFE_METHODS:
            # No permissions required for GET requests
            self.required_permissions = []
        else:
            # Require permission for non-GET requests
            self.required_permissions = [Permissions.MANAGE_PROVIDERS]

    def get_queryset(self):
        user_roles = get_role(self.request.user)
        # Check if any of the user's roles have UNLIMITED_VISIBILITY
        if user_roles.unlimited_visibility:
            # User has unlimited visibility, return all provider groups
            return ProviderGroup.objects.prefetch_related("providers", "roles")

        # Collect provider groups associated with the user's roles
        return user_roles.provider_groups.all().prefetch_related("providers", "roles")

    def get_serializer_class(self):
        if self.action == "create":
            return ProviderGroupCreateSerializer
        elif self.action == "partial_update":
            return ProviderGroupUpdateSerializer
        return super().get_serializer_class()


@extend_schema(tags=["Provider Group"])
@extend_schema_view(
    create=extend_schema(
        summary="Create a new provider_group-providers relationship",
        description="Add a new provider_group-providers relationship to the system by providing the required provider_group-providers details.",
        responses={
            204: OpenApiResponse(description="Relationship created successfully"),
            400: OpenApiResponse(
                description="Bad request (e.g., relationship already exists)"
            ),
        },
    ),
    partial_update=extend_schema(
        summary="Partially update a provider_group-providers relationship",
        description="Update the provider_group-providers relationship information without affecting other fields.",
        responses={
            204: OpenApiResponse(
                response=None, description="Relationship updated successfully"
            )
        },
    ),
    destroy=extend_schema(
        summary="Delete a provider_group-providers relationship",
        description="Remove the provider_group-providers relationship from the system by their ID.",
        responses={
            204: OpenApiResponse(
                response=None, description="Relationship deleted successfully"
            )
        },
    ),
)
class ProviderGroupProvidersRelationshipView(RelationshipView, BaseRLSViewSet):
    queryset = ProviderGroup.objects.all()
    serializer_class = ProviderGroupMembershipSerializer
    resource_name = "providers"
    http_method_names = ["post", "patch", "delete"]
    schema = RelationshipViewSchema()
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_PROVIDERS]

    def get_queryset(self):
        return ProviderGroup.objects.filter(tenant_id=self.request.tenant_id)

    def create(self, request, *args, **kwargs):
        provider_group = self.get_object()

        provider_ids = [item["id"] for item in request.data]
        existing_relationships = ProviderGroupMembership.objects.filter(
            provider_group=provider_group, provider_id__in=provider_ids
        )

        if existing_relationships.exists():
            return Response(
                {
                    "detail": "One or more providers are already associated with the provider_group."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = self.get_serializer(
            data={"providers": request.data},
            context={
                "provider_group": provider_group,
                "tenant_id": self.request.tenant_id,
                "request": request,
            },
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)

    def partial_update(self, request, *args, **kwargs):
        provider_group = self.get_object()
        serializer = self.get_serializer(
            instance=provider_group,
            data={"providers": request.data},
            context={"tenant_id": self.request.tenant_id, "request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def destroy(self, request, *args, **kwargs):
        provider_group = self.get_object()
        provider_group.providers.clear()

        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    list=extend_schema(
        tags=["Provider"],
        summary="List all providers",
        description="Retrieve a list of all providers with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        tags=["Provider"],
        summary="Retrieve data from a provider",
        description="Fetch detailed information about a specific provider by their ID.",
    ),
    create=extend_schema(
        tags=["Provider"],
        summary="Create a new provider",
        description="Add a new provider to the system by providing the required provider details.",
    ),
    partial_update=extend_schema(
        tags=["Provider"],
        summary="Partially update a provider",
        description="Update certain fields of an existing provider's information without affecting other fields.",
        request=ProviderUpdateSerializer,
        responses={200: ProviderSerializer},
    ),
    destroy=extend_schema(
        tags=["Provider"],
        summary="Delete a provider",
        description="Remove a provider from the system by their ID.",
        responses={202: OpenApiResponse(response=TaskSerializer)},
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ProviderViewSet(DisablePaginationMixin, BaseRLSViewSet):
    queryset = Provider.objects.all()
    serializer_class = ProviderSerializer
    http_method_names = ["get", "post", "patch", "delete"]
    filterset_class = ProviderFilter
    search_fields = ["provider", "uid", "alias"]
    ordering = ["-inserted_at"]
    ordering_fields = [
        "provider",
        "uid",
        "alias",
        "connected",
        "inserted_at",
        "updated_at",
    ]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_PROVIDERS]

    def set_required_permissions(self):
        """
        Returns the required permissions based on the request method.
        """
        if self.request.method in SAFE_METHODS:
            # No permissions required for GET requests
            self.required_permissions = []
        else:
            # Require permission for non-GET requests
            self.required_permissions = [Permissions.MANAGE_PROVIDERS]

    def get_queryset(self):
        user_roles = get_role(self.request.user)
        if user_roles.unlimited_visibility:
            # User has unlimited visibility, return all providers
            queryset = Provider.objects.filter(tenant_id=self.request.tenant_id)
        else:
            # User lacks permission, filter providers based on provider groups associated with the role
            queryset = get_providers(user_roles)
        return queryset.select_related("secret").prefetch_related("provider_groups")

    def get_serializer_class(self):
        if self.action == "create":
            return ProviderCreateSerializer
        elif self.action == "partial_update":
            return ProviderUpdateSerializer
        elif self.action in ["connection", "destroy"]:
            return TaskSerializer
        return super().get_serializer_class()

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(
            instance,
            data=request.data,
            partial=True,
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        read_serializer = ProviderSerializer(
            instance, context=self.get_serializer_context()
        )
        return Response(data=read_serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        tags=["Provider"],
        summary="Check connection",
        description="Try to verify connection. For instance, Role & Credentials are set correctly",
        request=None,
        responses={202: OpenApiResponse(response=TaskSerializer)},
    )
    @action(detail=True, methods=["post"], url_name="connection")
    def connection(self, request, pk=None):
        get_object_or_404(Provider, pk=pk)
        with transaction.atomic():
            task = check_provider_connection_task.delay(
                provider_id=pk, tenant_id=self.request.tenant_id
            )
        prowler_task = Task.objects.get(id=task.id)
        serializer = TaskSerializer(prowler_task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": prowler_task.id}
                )
            },
        )

    def destroy(self, request, *args, pk=None, **kwargs):
        provider = get_object_or_404(Provider, pk=pk)
        provider.is_deleted = True
        provider.save()
        task_name = f"scan-perform-scheduled-{pk}"
        PeriodicTask.objects.filter(name=task_name).update(enabled=False)

        with transaction.atomic():
            task = delete_provider_task.delay(
                provider_id=pk, tenant_id=self.request.tenant_id
            )
        prowler_task = Task.objects.get(id=task.id)
        serializer = TaskSerializer(prowler_task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": prowler_task.id}
                )
            },
        )


@extend_schema_view(
    list=extend_schema(
        tags=["Scan"],
        summary="List all scans",
        description="Retrieve a list of all scans with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        tags=["Scan"],
        summary="Retrieve data from a specific scan",
        description="Fetch detailed information about a specific scan by its ID.",
    ),
    partial_update=extend_schema(
        tags=["Scan"],
        summary="Partially update a scan",
        description="Update certain fields of an existing scan without affecting other fields.",
    ),
    create=extend_schema(
        tags=["Scan"],
        summary="Trigger a manual scan",
        description=(
            "Trigger a manual scan by providing the required scan details. "
            "If `scanner_args` are not provided, the system will automatically use the default settings "
            "from the associated provider. If you do provide `scanner_args`, these settings will be "
            "merged with the provider's defaults. This means that your provided settings will override "
            "the defaults only where they conflict, while the rest of the default settings will remain intact."
        ),
        request=ScanCreateSerializer,
        responses={202: OpenApiResponse(response=TaskSerializer)},
    ),
    report=extend_schema(
        tags=["Scan"],
        summary="Download ZIP report",
        description="Returns a ZIP file containing the requested report",
        request=ScanReportSerializer,
        responses={
            200: OpenApiResponse(description="Report obtained successfully"),
            202: OpenApiResponse(description="The task is in progress"),
            403: OpenApiResponse(description="There is a problem with credentials"),
            404: OpenApiResponse(
                description="The scan has no reports, or the report generation task has not started yet"
            ),
        },
    ),
    compliance=extend_schema(
        tags=["Scan"],
        summary="Retrieve compliance report as CSV",
        description="Download a specific compliance report (e.g., 'cis_1.4_aws') as a CSV file.",
        parameters=[
            OpenApiParameter(
                name="name",
                type=str,
                location=OpenApiParameter.PATH,
                required=True,
                description="The compliance report name, like 'cis_1.4_aws'",
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="CSV file containing the compliance report"
            ),
            404: OpenApiResponse(description="Compliance report not found"),
        },
        request=None,
    ),
    threatscore=extend_schema(
        tags=["Scan"],
        summary="Retrieve threatscore report",
        description="Download a specific threatscore report (e.g., 'prowler_threatscore_aws') as a PDF file.",
        request=None,
        responses={
            200: OpenApiResponse(
                description="PDF file containing the threatscore report"
            ),
            202: OpenApiResponse(description="The task is in progress"),
            401: OpenApiResponse(
                description="API key missing or user not Authenticated"
            ),
            403: OpenApiResponse(description="There is a problem with credentials"),
            404: OpenApiResponse(
                description="The scan has no threatscore reports, or the threatscore report generation task has not started yet"
            ),
        },
    ),
    ens=extend_schema(
        tags=["Scan"],
        summary="Retrieve ENS RD2022 compliance report",
        description="Download ENS RD2022 compliance report (e.g., 'ens_rd2022_aws') as a PDF file.",
        request=None,
        responses={
            200: OpenApiResponse(
                description="PDF file containing the ENS compliance report"
            ),
            202: OpenApiResponse(description="The task is in progress"),
            401: OpenApiResponse(
                description="API key missing or user not Authenticated"
            ),
            403: OpenApiResponse(description="There is a problem with credentials"),
            404: OpenApiResponse(
                description="The scan has no ENS reports, or the ENS report generation task has not started yet"
            ),
        },
    ),
    nis2=extend_schema(
        tags=["Scan"],
        summary="Retrieve NIS2 compliance report",
        description="Download NIS2 compliance report (Directive (EU) 2022/2555) as a PDF file.",
        request=None,
        responses={
            200: OpenApiResponse(
                description="PDF file containing the NIS2 compliance report"
            ),
            202: OpenApiResponse(description="The task is in progress"),
            401: OpenApiResponse(
                description="API key missing or user not Authenticated"
            ),
            403: OpenApiResponse(description="There is a problem with credentials"),
            404: OpenApiResponse(
                description="The scan has no NIS2 reports, or the NIS2 report generation task has not started yet"
            ),
        },
    ),
    csa=extend_schema(
        tags=["Scan"],
        summary="Retrieve CSA CCM compliance report",
        description="Download CSA Cloud Controls Matrix (CCM) v4.0 compliance report as a PDF file.",
        request=None,
        responses={
            200: OpenApiResponse(
                description="PDF file containing the CSA CCM compliance report"
            ),
            202: OpenApiResponse(description="The task is in progress"),
            401: OpenApiResponse(
                description="API key missing or user not Authenticated"
            ),
            403: OpenApiResponse(description="There is a problem with credentials"),
            404: OpenApiResponse(
                description="The scan has no CSA CCM reports, or the CSA CCM report generation task has not started yet"
            ),
        },
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ScanViewSet(BaseRLSViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    http_method_names = ["get", "post", "patch"]
    filterset_class = ScanFilter
    ordering = ["-inserted_at"]
    ordering_fields = [
        "name",
        "trigger",
        "attempted_at",
        "scheduled_at",
        "inserted_at",
        "updated_at",
    ]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_SCANS]

    def set_required_permissions(self):
        """
        Returns the required permissions based on the request method.
        """
        if self.request.method in SAFE_METHODS:
            # No permissions required for GET requests
            self.required_permissions = []
        else:
            # Require permission for non-GET requests
            self.required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        user_roles = get_role(self.request.user)
        if user_roles.unlimited_visibility:
            # User has unlimited visibility, return all scans
            queryset = Scan.objects.filter(tenant_id=self.request.tenant_id)
        else:
            # User lacks permission, filter providers based on provider groups associated with the role
            queryset = Scan.objects.filter(provider__in=get_providers(user_roles))
        return queryset.select_related("provider", "task")

    def get_serializer_class(self):
        if self.action == "create":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
            return ScanCreateSerializer
        elif self.action == "partial_update":
            return ScanUpdateSerializer
        elif self.action == "report":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
            return ScanReportSerializer
        elif self.action == "compliance":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
            return ScanComplianceReportSerializer
        elif self.action == "threatscore":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
        elif self.action == "ens":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
        elif self.action == "nis2":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
        elif self.action == "csa":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
        return super().get_serializer_class()

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(
            instance,
            data=request.data,
            partial=True,
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        read_serializer = ScanSerializer(
            instance, context=self.get_serializer_context()
        )
        return Response(data=read_serializer.data, status=status.HTTP_200_OK)

    def _get_task_status(self, scan_instance):
        """
        Returns task status if the scan or its associated report-generation task is still executing.

        If the scan is in an EXECUTING state or if a background task related to report generation
        is found and also executing, this method returns a 202 Accepted response with the task
        metadata and a `Content-Location` header pointing to the task detail endpoint.

        Args:
            scan_instance (Scan): The scan instance for which the task status is being checked.

        Returns:
            Response or None:
                - A `Response` with HTTP 202 status and serialized task data if the task is executing.
                - `None` if no running task is found or if the task has already completed.
        """
        task = None

        if scan_instance.state == StateChoices.EXECUTING and scan_instance.task:
            task = scan_instance.task
        else:
            try:
                task = Task.objects.get(
                    task_runner_task__task_name="scan-report",
                    task_runner_task__task_kwargs__contains=str(scan_instance.id),
                )
            except Task.DoesNotExist:
                return None

        self.response_serializer_class = TaskSerializer
        serializer = self.get_serializer(task)

        if serializer.data.get("state") != StateChoices.EXECUTING:
            return None

        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": serializer.data["id"]}
                )
            },
        )

    def _load_file(self, path_pattern, s3=False, bucket=None, list_objects=False):
        """
        Loads a binary file (e.g., ZIP or CSV) and returns its content and filename.

        Depending on the input parameters, this method supports loading:
        - From S3 using a direct key.
        - From S3 by listing objects under a prefix and matching suffix.
        - From the local filesystem using glob pattern matching.

        Args:
            path_pattern (str): The key or glob pattern representing the file location.
            s3 (bool, optional): Whether the file is stored in S3. Defaults to False.
            bucket (str, optional): The name of the S3 bucket, required if `s3=True`. Defaults to None.
            list_objects (bool, optional): If True and `s3=True`, list objects by prefix to find the file. Defaults to False.

        Returns:
            tuple[bytes, str]: A tuple containing the file content as bytes and the filename if successful.
            Response: A DRF `Response` object with an appropriate status and error detail if an error occurs.
        """
        if s3:
            try:
                client = get_s3_client()
            except (ClientError, NoCredentialsError, ParamValidationError):
                return Response(
                    {"detail": "There is a problem with credentials."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            if list_objects:
                # list keys under prefix then match suffix
                prefix = os.path.dirname(path_pattern)
                suffix = os.path.basename(path_pattern)
                try:
                    resp = client.list_objects_v2(Bucket=bucket, Prefix=prefix)
                except ClientError as e:
                    sentry_sdk.capture_exception(e)
                    return Response(
                        {
                            "detail": "Unable to list compliance files in S3: encountered an AWS error."
                        },
                        status=status.HTTP_502_BAD_GATEWAY,
                    )
                contents = resp.get("Contents", [])
                keys = []
                for obj in contents:
                    key = obj["Key"]
                    key_basename = os.path.basename(key)
                    if any(ch in suffix for ch in ("*", "?", "[")):
                        if fnmatch.fnmatch(key_basename, suffix):
                            keys.append(key)
                    elif key_basename == suffix:
                        keys.append(key)
                    elif key.endswith(suffix):
                        # Backward compatibility if suffix already includes directories
                        keys.append(key)
                if not keys:
                    return Response(
                        {
                            "detail": f"No compliance file found for name '{os.path.splitext(suffix)[0]}'."
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )
                # path_pattern here is prefix, but in compliance we build correct suffix check before
                key = keys[0]
            else:
                # path_pattern is exact key
                key = path_pattern
            try:
                s3_obj = client.get_object(Bucket=bucket, Key=key)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code == "NoSuchKey":
                    return Response(
                        {
                            "detail": "The scan has no reports, or the report generation task has not started yet."
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )
                return Response(
                    {"detail": "There is a problem with credentials."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            content = s3_obj["Body"].read()
            filename = os.path.basename(key)
        else:
            files = glob.glob(path_pattern)
            if not files:
                return Response(
                    {
                        "detail": "The scan has no reports, or the report generation task has not started yet."
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )
            filepath = files[0]
            with open(filepath, "rb") as f:
                content = f.read()
            filename = os.path.basename(filepath)

        return content, filename

    def _serve_file(self, content, filename, content_type):
        response = HttpResponse(content, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="{filename}"'

        return response

    @action(detail=True, methods=["get"], url_name="report")
    def report(self, request, pk=None):
        scan = self.get_object()
        # Check for executing tasks
        running_resp = self._get_task_status(scan)
        if running_resp:
            return running_resp

        if not scan.output_location:
            return Response(
                {
                    "detail": "The scan has no reports, or the report generation task has not started yet."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if scan.output_location.startswith("s3://"):
            bucket = env.str("DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET", "")
            key_prefix = scan.output_location.removeprefix(f"s3://{bucket}/")
            loader = self._load_file(
                key_prefix, s3=True, bucket=bucket, list_objects=False
            )
        else:
            loader = self._load_file(scan.output_location, s3=False)

        if isinstance(loader, Response):
            return loader

        content, filename = loader
        return self._serve_file(content, filename, "application/x-zip-compressed")

    @action(
        detail=True,
        methods=["get"],
        url_path="compliance/(?P<name>[^/]+)",
        url_name="compliance",
    )
    def compliance(self, request, pk=None, name=None):
        scan = self.get_object()
        if name not in get_compliance_frameworks(scan.provider.provider):
            return Response(
                {"detail": f"Compliance '{name}' not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        running_resp = self._get_task_status(scan)
        if running_resp:
            return running_resp

        if not scan.output_location:
            return Response(
                {
                    "detail": "The scan has no reports, or the report generation task has not started yet."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if scan.output_location.startswith("s3://"):
            bucket = env.str("DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET", "")
            key_prefix = scan.output_location.removeprefix(f"s3://{bucket}/")
            prefix = os.path.join(
                os.path.dirname(key_prefix), "compliance", f"{name}.csv"
            )
            loader = self._load_file(prefix, s3=True, bucket=bucket, list_objects=True)
        else:
            base = os.path.dirname(scan.output_location)
            pattern = os.path.join(base, "compliance", f"*_{name}.csv")
            loader = self._load_file(pattern, s3=False)

        if isinstance(loader, Response):
            return loader

        content, filename = loader
        return self._serve_file(content, filename, "text/csv")

    @action(
        detail=True,
        methods=["get"],
        url_name="threatscore",
    )
    def threatscore(self, request, pk=None):
        scan = self.get_object()
        running_resp = self._get_task_status(scan)
        if running_resp:
            return running_resp

        # TODO: add detailed response if the compliance framework is not supported for the provider
        if not scan.output_location:
            return Response(
                {
                    "detail": "The scan has no reports, or the threatscore report generation task has not started yet."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if scan.output_location.startswith("s3://"):
            bucket = env.str("DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET", "")
            key_prefix = scan.output_location.removeprefix(f"s3://{bucket}/")
            prefix = os.path.join(
                os.path.dirname(key_prefix),
                "threatscore",
                "*_threatscore_report.pdf",
            )
            loader = self._load_file(prefix, s3=True, bucket=bucket, list_objects=True)
        else:
            base = os.path.dirname(scan.output_location)
            pattern = os.path.join(base, "threatscore", "*_threatscore_report.pdf")
            loader = self._load_file(pattern, s3=False)

        if isinstance(loader, Response):
            return loader

        content, filename = loader
        return self._serve_file(content, filename, "application/pdf")

    @action(
        detail=True,
        methods=["get"],
        url_name="ens",
    )
    def ens(self, request, pk=None):
        scan = self.get_object()
        running_resp = self._get_task_status(scan)
        if running_resp:
            return running_resp

        # TODO: add detailed response if the compliance framework is not supported for the provider
        if not scan.output_location:
            return Response(
                {
                    "detail": "The scan has no reports, or the ENS report generation task has not started yet."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if scan.output_location.startswith("s3://"):
            bucket = env.str("DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET", "")
            key_prefix = scan.output_location.removeprefix(f"s3://{bucket}/")
            prefix = os.path.join(
                os.path.dirname(key_prefix),
                "ens",
                "*_ens_report.pdf",
            )
            loader = self._load_file(prefix, s3=True, bucket=bucket, list_objects=True)
        else:
            base = os.path.dirname(scan.output_location)
            pattern = os.path.join(base, "ens", "*_ens_report.pdf")
            loader = self._load_file(pattern, s3=False)

        if isinstance(loader, Response):
            return loader

        content, filename = loader
        return self._serve_file(content, filename, "application/pdf")

    @action(
        detail=True,
        methods=["get"],
        url_name="nis2",
    )
    def nis2(self, request, pk=None):
        scan = self.get_object()
        running_resp = self._get_task_status(scan)
        if running_resp:
            return running_resp

        if not scan.output_location:
            return Response(
                {
                    "detail": "The scan has no reports, or the NIS2 report generation task has not started yet."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if scan.output_location.startswith("s3://"):
            bucket = env.str("DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET", "")
            key_prefix = scan.output_location.removeprefix(f"s3://{bucket}/")
            prefix = os.path.join(
                os.path.dirname(key_prefix),
                "nis2",
                "*_nis2_report.pdf",
            )
            loader = self._load_file(prefix, s3=True, bucket=bucket, list_objects=True)
        else:
            base = os.path.dirname(scan.output_location)
            pattern = os.path.join(base, "nis2", "*_nis2_report.pdf")
            loader = self._load_file(pattern, s3=False)

        if isinstance(loader, Response):
            return loader

        content, filename = loader
        return self._serve_file(content, filename, "application/pdf")

    @action(
        detail=True,
        methods=["get"],
        url_name="csa",
    )
    def csa(self, request, pk=None):
        scan = self.get_object()
        running_resp = self._get_task_status(scan)
        if running_resp:
            return running_resp

        if not scan.output_location:
            return Response(
                {
                    "detail": "The scan has no reports, or the CSA CCM report generation task has not started yet."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if scan.output_location.startswith("s3://"):
            bucket = env.str("DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET", "")
            key_prefix = scan.output_location.removeprefix(f"s3://{bucket}/")
            prefix = os.path.join(
                os.path.dirname(key_prefix),
                "csa",
                "*_csa_report.pdf",
            )
            loader = self._load_file(prefix, s3=True, bucket=bucket, list_objects=True)
        else:
            base = os.path.dirname(scan.output_location)
            pattern = os.path.join(base, "csa", "*_csa_report.pdf")
            loader = self._load_file(pattern, s3=False)

        if isinstance(loader, Response):
            return loader

        content, filename = loader
        return self._serve_file(content, filename, "application/pdf")

    def create(self, request, *args, **kwargs):
        input_serializer = self.get_serializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            scan = input_serializer.save()
        with transaction.atomic():
            task = perform_scan_task.apply_async(
                kwargs={
                    "tenant_id": self.request.tenant_id,
                    "scan_id": str(scan.id),
                    "provider_id": str(scan.provider_id),
                    # Disabled for now
                    # checks_to_execute=scan.scanner_args.get("checks_to_execute")
                },
            )

        attack_paths_db_utils.create_attack_paths_scan(
            tenant_id=self.request.tenant_id,
            scan_id=str(scan.id),
            provider_id=str(scan.provider_id),
        )

        prowler_task = Task.objects.get(id=task.id)
        scan.task_id = task.id
        scan.save(update_fields=["task_id"])

        self.response_serializer_class = TaskSerializer
        output_serializer = self.get_serializer(prowler_task)

        return Response(
            data=output_serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": prowler_task.id}
                )
            },
        )


@extend_schema_view(
    list=extend_schema(
        tags=["Task"],
        summary="List all tasks",
        description="Retrieve a list of all tasks with options for filtering by name, state, and other criteria.",
    ),
    retrieve=extend_schema(
        tags=["Task"],
        summary="Retrieve data from a specific task",
        description="Fetch detailed information about a specific task by its ID.",
    ),
    destroy=extend_schema(
        tags=["Task"],
        summary="Revoke a task",
        description="Try to revoke a task using its ID. Only tasks that are not yet in progress can be revoked.",
        responses={202: OpenApiResponse(response=TaskSerializer)},
    ),
)
class TaskViewSet(BaseRLSViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    http_method_names = ["get", "delete"]
    filterset_class = TaskFilter
    search_fields = ["name"]
    ordering = ["-inserted_at"]
    ordering_fields = ["inserted_at", "completed_at", "name", "state"]
    # RBAC required permissions
    required_permissions = []

    def get_queryset(self):
        return Task.objects.annotate(
            name=F("task_runner_task__task_name"),
            state=F("task_runner_task__status"),
        ).select_related("task_runner_task")

    def destroy(self, request, *args, pk=None, **kwargs):
        task = get_object_or_404(Task, pk=pk)
        if task.task_runner_task.status not in ["PENDING", "RECEIVED"]:
            serializer = TaskSerializer(task)
            return Response(
                data={
                    "detail": f"Task cannot be revoked. Status: '{serializer.data.get('state')}'"
                },
                status=status.HTTP_400_BAD_REQUEST,
                headers={
                    "Content-Location": reverse("task-detail", kwargs={"pk": task.id})
                },
            )

        task_instance = AsyncResult(pk)
        task_instance.revoke()
        task.refresh_from_db()
        serializer = TaskSerializer(task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse("task-detail", kwargs={"pk": task.id})
            },
        )


@extend_schema_view(
    list=extend_schema(
        tags=["Attack Paths"],
        summary="List Attack Paths scans",
        description="Retrieve Attack Paths scans for the tenant with support for filtering, ordering, and pagination.",
    ),
    retrieve=extend_schema(
        tags=["Attack Paths"],
        summary="Retrieve Attack Paths scan details",
        description="Fetch full details for a specific Attack Paths scan.",
    ),
    attack_paths_queries=extend_schema(
        tags=["Attack Paths"],
        summary="List Attack Paths queries",
        description="Retrieve the catalog of Attack Paths queries available for this Attack Paths scan.",
        responses={
            200: OpenApiResponse(AttackPathsQuerySerializer(many=True)),
            404: OpenApiResponse(
                description="No queries found for the selected provider"
            ),
        },
    ),
    run_attack_paths_query=extend_schema(
        tags=["Attack Paths"],
        summary="Execute an Attack Paths query",
        description="Execute the selected Attack Paths query against the Attack Paths graph and return the resulting subgraph.",
        request=AttackPathsQueryRunRequestSerializer,
        responses={
            200: OpenApiResponse(AttackPathsQueryResultSerializer),
            400: OpenApiResponse(
                description="Bad request (e.g., Unknown Attack Paths query for the selected provider)"
            ),
            404: OpenApiResponse(
                description="No Attack Paths found for the given query and parameters"
            ),
            500: OpenApiResponse(
                description="Attack Paths query execution failed due to a database error"
            ),
        },
    ),
)
class AttackPathsScanViewSet(BaseRLSViewSet):
    queryset = AttackPathsScan.objects.all()
    serializer_class = AttackPathsScanSerializer
    http_method_names = ["get", "post"]
    filterset_class = AttackPathsScanFilter
    ordering = ["-inserted_at"]
    ordering_fields = [
        "inserted_at",
        "started_at",
    ]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_SCANS]

    def set_required_permissions(self):
        if self.request.method in SAFE_METHODS:
            self.required_permissions = []

        else:
            self.required_permissions = [Permissions.MANAGE_SCANS]

    def get_serializer_class(self):
        if self.action == "run_attack_paths_query":
            return AttackPathsQueryRunRequestSerializer

        return super().get_serializer_class()

    def get_queryset(self):
        user_roles = get_role(self.request.user)
        base_queryset = AttackPathsScan.objects.filter(tenant_id=self.request.tenant_id)

        if user_roles.unlimited_visibility:
            queryset = base_queryset

        else:
            queryset = base_queryset.filter(provider__in=get_providers(user_roles))

        return queryset.select_related("provider", "scan", "task")

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        latest_per_provider = queryset.annotate(
            latest_scan_rank=Window(
                expression=RowNumber(),
                partition_by=[F("provider_id")],
                order_by=[F("inserted_at").desc()],
            )
        ).filter(latest_scan_rank=1)

        page = self.paginate_queryset(latest_per_provider)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(latest_per_provider, many=True)
        return Response(serializer.data)

    @extend_schema(exclude=True)
    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="POST")

    @extend_schema(exclude=True)
    def destroy(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="DELETE")

    @action(
        detail=True,
        methods=["get"],
        url_path="queries",
        url_name="queries",
    )
    def attack_paths_queries(self, request, pk=None):
        attack_paths_scan = self.get_object()
        queries = get_queries_for_provider(attack_paths_scan.provider.provider)

        if not queries:
            return Response(
                {"detail": "No queries found for the selected provider"},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = AttackPathsQuerySerializer(queries, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(
        detail=True,
        methods=["post"],
        url_path="queries/run",
        url_name="queries-run",
    )
    def run_attack_paths_query(self, request, pk=None):
        attack_paths_scan = self.get_object()

        if not attack_paths_scan.graph_data_ready:
            raise ValidationError(
                {
                    "detail": "Attack Paths data is not available for querying - a scan must complete at least once before queries can be run"
                }
            )

        payload = attack_paths_views_helpers.normalize_run_payload(request.data)
        serializer = AttackPathsQueryRunRequestSerializer(data=payload)
        serializer.is_valid(raise_exception=True)

        query_definition = get_query_by_id(serializer.validated_data["id"])
        if (
            query_definition is None
            or query_definition.provider != attack_paths_scan.provider.provider
        ):
            raise ValidationError(
                {"id": "Unknown Attack Paths query for the selected provider"}
            )

        database_name = graph_database.get_database_name(
            attack_paths_scan.provider.tenant_id
        )
        provider_id = str(attack_paths_scan.provider_id)
        parameters = attack_paths_views_helpers.prepare_query_parameters(
            query_definition,
            serializer.validated_data.get("parameters", {}),
            attack_paths_scan.provider.uid,
            provider_id,
        )

        graph = attack_paths_views_helpers.execute_attack_paths_query(
            database_name,
            query_definition,
            parameters,
            provider_id,
        )
        graph_database.clear_cache(database_name)

        status_code = status.HTTP_200_OK
        if not graph.get("nodes"):
            status_code = status.HTTP_404_NOT_FOUND

        response_serializer = AttackPathsQueryResultSerializer(graph)
        return Response(response_serializer.data, status=status_code)


@extend_schema_view(
    list=extend_schema(
        tags=["Resource"],
        summary="List all resources",
        description="Retrieve a list of all resources with options for filtering by various criteria. Resources are "
        "objects that are discovered by Prowler. They can be anything from a single host to a whole VPC.",
        parameters=[
            OpenApiParameter(
                name="filter[updated_at]",
                description="At least one of the variations of the `filter[updated_at]` filter must be provided.",
                required=True,
                type=OpenApiTypes.DATE,
            )
        ],
    ),
    retrieve=extend_schema(
        tags=["Resource"],
        summary="Retrieve data for a resource",
        description="Fetch detailed information about a specific resource by their ID. A Resource is an object that "
        "is discovered by Prowler. It can be anything from a single host to a whole VPC.",
    ),
    metadata=extend_schema(
        tags=["Resource"],
        summary="Retrieve metadata values from resources",
        description="Fetch unique metadata values from a set of resources. This is useful for dynamic filtering.",
        parameters=[
            OpenApiParameter(
                name="filter[updated_at]",
                description="At least one of the variations of the `filter[updated_at]` filter must be provided.",
                required=True,
                type=OpenApiTypes.DATE,
            )
        ],
        filters=True,
    ),
    latest=extend_schema(
        tags=["Resource"],
        summary="List the latest resources",
        description="Retrieve a list of the latest resources from the latest scans for each provider with options for "
        "filtering by various criteria.",
        filters=True,
    ),
    metadata_latest=extend_schema(
        tags=["Resource"],
        summary="Retrieve metadata values from the latest resources",
        description="Fetch unique metadata values from a set of resources from the latest scans for each provider. "
        "This is useful for dynamic filtering.",
        filters=True,
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ResourceViewSet(PaginateByPkMixin, BaseRLSViewSet):
    queryset = Resource.all_objects.all()
    serializer_class = ResourceSerializer
    http_method_names = ["get"]
    filterset_class = ResourceFilter
    ordering = ["-failed_findings_count", "-updated_at"]

    # Events endpoint constants (currently AWS-only, limited to 90 days by CloudTrail Event History)
    EVENTS_DEFAULT_LOOKBACK_DAYS = 90
    EVENTS_MIN_LOOKBACK_DAYS = 1
    EVENTS_MAX_LOOKBACK_DAYS = 90
    # Page size controls how many events CloudTrail returns (prepares for API pagination)
    EVENTS_DEFAULT_PAGE_SIZE = 50
    EVENTS_MIN_PAGE_SIZE = 1
    EVENTS_MAX_PAGE_SIZE = 50  # CloudTrail lookup_events max is 50
    # Allowed query parameters for the events endpoint
    EVENTS_ALLOWED_PARAMS = frozenset(
        {"lookback_days", "page[size]", "include_read_events"}
    )

    ordering_fields = [
        "provider_uid",
        "uid",
        "name",
        "region",
        "service",
        "type",
        "inserted_at",
        "updated_at",
    ]
    prefetch_for_includes = {
        "__all__": [],
        "provider": [
            Prefetch(
                "provider", queryset=Provider.all_objects.select_related("resources")
            )
        ],
    }
    # RBAC required permissions (implicit -> MANAGE_PROVIDERS enable unlimited visibility or check the visibility of
    # the provider through the provider group)
    required_permissions = []

    def get_queryset(self):
        user_roles = get_role(self.request.user)
        if user_roles.unlimited_visibility:
            # User has unlimited visibility, return all scans
            queryset = Resource.all_objects.filter(tenant_id=self.request.tenant_id)
        else:
            # User lacks permission, filter providers based on provider groups associated with the role
            queryset = Resource.all_objects.filter(
                tenant_id=self.request.tenant_id, provider__in=get_providers(user_roles)
            )

        search_value = self.request.query_params.get("filter[search]", None)
        if search_value:
            search_query = SearchQuery(
                search_value, config="simple", search_type="plain"
            )
            queryset = queryset.filter(
                Q(text_search=search_query) | Q(tags__text_search=search_query)
            ).distinct()

        return queryset

    def _optimize_tags_loading(self, queryset):
        """Optimize tags loading with prefetch_related to avoid N+1 queries"""
        # Use prefetch_related to load all tags in a single query
        return queryset.prefetch_related(
            Prefetch(
                "tags",
                queryset=ResourceTag.objects.filter(
                    tenant_id=self.request.tenant_id
                ).select_related(),
                to_attr="prefetched_tags",
            )
        )

    def _should_prefetch_findings(self) -> bool:
        fields_param = self.request.query_params.get("fields[resources]", "")
        include_param = self.request.query_params.get("include", "")
        return (
            fields_param == ""
            or "findings" in fields_param.split(",")
            or "findings" in include_param.split(",")
        )

    def _get_findings_prefetch(self):
        findings_queryset = Finding.all_objects.defer("scan", "resources").filter(
            tenant_id=self.request.tenant_id
        )
        return [Prefetch("findings", queryset=findings_queryset)]

    def get_serializer_class(self):
        if self.action in ["metadata", "metadata_latest"]:
            return ResourceMetadataSerializer
        if self.action == "events":
            return ResourceEventSerializer
        return super().get_serializer_class()

    def get_filterset_class(self):
        if self.action in ["latest", "metadata_latest"]:
            return LatestResourceFilter
        return ResourceFilter

    def filter_queryset(self, queryset):
        # Do not apply filters when retrieving specific resource or events
        if self.action in ["retrieve", "events"]:
            return queryset
        return super().filter_queryset(queryset)

    def list(self, request, *args, **kwargs):
        filtered_queryset = self.filter_queryset(self.get_queryset())
        return self.paginate_by_pk(
            request,
            filtered_queryset,
            manager=Resource.all_objects,
            select_related=["provider"],
            prefetch_related=(
                self._get_findings_prefetch()
                if self._should_prefetch_findings()
                else []
            ),
        )

    def retrieve(self, request, *args, **kwargs):
        queryset = self._optimize_tags_loading(self.get_queryset())
        instance = get_object_or_404(queryset, pk=kwargs.get("pk"))
        mapping_ids = list(
            ResourceFindingMapping.objects.filter(
                resource=instance, tenant_id=request.tenant_id
            ).values_list("finding_id", flat=True)
        )
        latest_findings = (
            Finding.all_objects.filter(id__in=mapping_ids, tenant_id=request.tenant_id)
            .order_by("uid", "-inserted_at")
            .distinct("uid")
        )
        setattr(instance, "latest_findings", latest_findings)
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_name="latest")
    def latest(self, request):
        tenant_id = request.tenant_id
        filtered_queryset = self.filter_queryset(self.get_queryset())

        latest_scans = (
            Scan.all_objects.filter(
                tenant_id=tenant_id,
                state=StateChoices.COMPLETED,
            )
            .order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
            .values("provider_id")
        )

        filtered_queryset = filtered_queryset.filter(
            provider_id__in=Subquery(latest_scans)
        )

        return self.paginate_by_pk(
            request,
            filtered_queryset,
            manager=Resource.all_objects,
            select_related=["provider"],
            prefetch_related=(
                self._get_findings_prefetch()
                if self._should_prefetch_findings()
                else []
            ),
        )

    @action(detail=False, methods=["get"], url_name="metadata")
    def metadata(self, request):
        # Force filter validation
        self.filter_queryset(self.get_queryset())

        tenant_id = request.tenant_id
        query_params = request.query_params

        queryset = ResourceScanSummary.objects.filter(tenant_id=tenant_id)

        if scans := query_params.get("filter[scan__in]") or query_params.get(
            "filter[scan]"
        ):
            queryset = queryset.filter(scan_id__in=scans.split(","))
        else:
            exact = query_params.get("filter[inserted_at]")
            gte = query_params.get("filter[inserted_at__gte]")
            lte = query_params.get("filter[inserted_at__lte]")

            date_filters = {}
            if exact:
                date = parse_date(exact)
                datetime_start = datetime.combine(
                    date, datetime.min.time(), tzinfo=timezone.utc
                )
                datetime_end = datetime_start + timedelta(days=1)
                date_filters["scan_id__gte"] = uuid7_start(
                    datetime_to_uuid7(datetime_start)
                )
                date_filters["scan_id__lt"] = uuid7_start(
                    datetime_to_uuid7(datetime_end)
                )
            else:
                if gte:
                    date_start = parse_date(gte)
                    datetime_start = datetime.combine(
                        date_start, datetime.min.time(), tzinfo=timezone.utc
                    )
                    date_filters["scan_id__gte"] = uuid7_start(
                        datetime_to_uuid7(datetime_start)
                    )
                if lte:
                    date_end = parse_date(lte)
                    datetime_end = datetime.combine(
                        date_end + timedelta(days=1),
                        datetime.min.time(),
                        tzinfo=timezone.utc,
                    )
                    date_filters["scan_id__lt"] = uuid7_start(
                        datetime_to_uuid7(datetime_end)
                    )

            if date_filters:
                queryset = queryset.filter(**date_filters)

        if service_filter := query_params.get("filter[service]") or query_params.get(
            "filter[service__in]"
        ):
            queryset = queryset.filter(service__in=service_filter.split(","))
        if region_filter := query_params.get("filter[region]") or query_params.get(
            "filter[region__in]"
        ):
            queryset = queryset.filter(region__in=region_filter.split(","))
        if resource_type_filter := query_params.get("filter[type]") or query_params.get(
            "filter[type__in]"
        ):
            queryset = queryset.filter(
                resource_type__in=resource_type_filter.split(",")
            )

        services = list(
            queryset.values_list("service", flat=True).distinct().order_by("service")
        )
        regions = list(
            queryset.values_list("region", flat=True).distinct().order_by("region")
        )
        resource_types = list(
            queryset.values_list("resource_type", flat=True)
            .exclude(resource_type__isnull=True)
            .exclude(resource_type__exact="")
            .distinct()
            .order_by("resource_type")
        )

        # Get groups from Resource model (flatten ArrayField)
        all_groups = Resource.objects.filter(
            tenant_id=tenant_id,
            groups__isnull=False,
        ).values_list("groups", flat=True)
        groups = sorted(
            set(g for groups_list in all_groups if groups_list for g in groups_list)
        )

        result = {
            "services": services,
            "regions": regions,
            "types": resource_types,
            "groups": groups,
        }

        serializer = self.get_serializer(data=result)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)

    @action(
        detail=False,
        methods=["get"],
        url_name="metadata_latest",
        url_path="metadata/latest",
    )
    def metadata_latest(self, request):
        tenant_id = request.tenant_id
        query_params = request.query_params

        latest_scans_queryset = (
            Scan.all_objects.filter(tenant_id=tenant_id, state=StateChoices.COMPLETED)
            .order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
        )

        queryset = ResourceScanSummary.objects.filter(
            tenant_id=tenant_id,
            scan_id__in=latest_scans_queryset.values_list("id", flat=True),
        )

        if service_filter := query_params.get("filter[service]") or query_params.get(
            "filter[service__in]"
        ):
            queryset = queryset.filter(service__in=service_filter.split(","))
        if region_filter := query_params.get("filter[region]") or query_params.get(
            "filter[region__in]"
        ):
            queryset = queryset.filter(region__in=region_filter.split(","))
        if resource_type_filter := query_params.get("filter[type]") or query_params.get(
            "filter[type__in]"
        ):
            queryset = queryset.filter(
                resource_type__in=resource_type_filter.split(",")
            )

        services = list(
            queryset.values_list("service", flat=True).distinct().order_by("service")
        )
        regions = list(
            queryset.values_list("region", flat=True).distinct().order_by("region")
        )
        resource_types = list(
            queryset.values_list("resource_type", flat=True)
            .exclude(resource_type__isnull=True)
            .exclude(resource_type__exact="")
            .distinct()
            .order_by("resource_type")
        )

        # Get groups from Resource model for resources in latest scans (flatten ArrayField)
        all_groups = Resource.objects.filter(
            tenant_id=tenant_id,
            groups__isnull=False,
        ).values_list("groups", flat=True)
        groups = sorted(
            set(g for groups_list in all_groups if groups_list for g in groups_list)
        )

        result = {
            "services": services,
            "regions": regions,
            "types": resource_types,
            "groups": groups,
        }

        serializer = self.get_serializer(data=result)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)

    @extend_schema(
        tags=["Resource"],
        summary="Get events for a resource",
        description=(
            "Retrieve events showing modification history for a resource. "
            "Returns who modified the resource and when. Currently only available for AWS resources.\n\n"
            "**Note:** Some events may not appear due to CloudTrail indexing limitations. "
            "Not all AWS API calls record the resource identifier in a searchable format."
        ),
        parameters=[
            OpenApiParameter(
                name="lookback_days",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description="Number of days to look back (default: 90, min: 1, max: 90).",
                required=False,
            ),
            OpenApiParameter(
                name="page[size]",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description="Maximum number of events to return (default: 50, min: 1, max: 50).",
                required=False,
            ),
            OpenApiParameter(
                name="include_read_events",
                type=OpenApiTypes.BOOL,
                location=OpenApiParameter.QUERY,
                description=(
                    "Include read-only events (Describe*, Get*, List*, etc.). "
                    "Default: false. Set to true to include all events."
                ),
                required=False,
            ),
            # NOTE: drf-spectacular auto-generates page[number] and fields[resource-events]
            # parameters. This endpoint does not support pagination (results are limited by
            # page[size] only) nor sparse fieldsets.
        ],
        responses={
            200: ResourceEventSerializer(many=True),
            400: OpenApiResponse(description="Invalid provider or parameters"),
            500: OpenApiResponse(description="Unexpected error retrieving events"),
            502: OpenApiResponse(
                description="Provider credentials invalid, expired, or lack required permissions"
            ),
            503: OpenApiResponse(description="Provider service unavailable"),
        },
    )
    @action(
        detail=True,
        methods=["get"],
        url_name="events",
        filter_backends=[],  # Disable filters - we're calling external API, not filtering queryset
    )
    def events(self, request, pk=None):
        """Get events for a resource."""
        resource = self.get_object()

        # Validate query parameters - reject unknown parameters
        for param in request.query_params.keys():
            if param not in self.EVENTS_ALLOWED_PARAMS:
                raise ValidationError(
                    [
                        {
                            "detail": f"invalid parameter '{param}'",
                            "status": "400",
                            "source": {"parameter": param},
                            "code": "invalid",
                        }
                    ]
                )

        # Validate provider - currently only AWS CloudTrail is supported
        if resource.provider.provider != Provider.ProviderChoices.AWS:
            raise ValidationError(
                [
                    {
                        "detail": "Events are only available for AWS resources",
                        "status": "400",
                        "source": {"pointer": "/data/attributes/provider"},
                        "code": "invalid_provider",
                    }
                ]
            )

        # Validate and parse lookback_days from query params
        lookback_days_str = request.query_params.get("lookback_days")
        if lookback_days_str is None:
            lookback_days = self.EVENTS_DEFAULT_LOOKBACK_DAYS
        else:
            try:
                lookback_days = int(lookback_days_str)
            except (ValueError, TypeError):
                raise ValidationError(
                    [
                        {
                            "detail": "lookback_days must be a valid integer",
                            "status": "400",
                            "source": {"parameter": "lookback_days"},
                            "code": "invalid",
                        }
                    ]
                )

            if not (
                self.EVENTS_MIN_LOOKBACK_DAYS
                <= lookback_days
                <= self.EVENTS_MAX_LOOKBACK_DAYS
            ):
                raise ValidationError(
                    [
                        {
                            "detail": (
                                f"lookback_days must be between {self.EVENTS_MIN_LOOKBACK_DAYS} "
                                f"and {self.EVENTS_MAX_LOOKBACK_DAYS}"
                            ),
                            "status": "400",
                            "source": {"parameter": "lookback_days"},
                            "code": "out_of_range",
                        }
                    ]
                )

        # Validate and parse page[size] from query params (JSON:API pagination)
        page_size_str = request.query_params.get("page[size]")
        if page_size_str is None:
            page_size = self.EVENTS_DEFAULT_PAGE_SIZE
        else:
            try:
                page_size = int(page_size_str)
            except (ValueError, TypeError):
                raise ValidationError(
                    [
                        {
                            "detail": "page[size] must be a valid integer",
                            "status": "400",
                            "source": {"parameter": "page[size]"},
                            "code": "invalid",
                        }
                    ]
                )

            if not (
                self.EVENTS_MIN_PAGE_SIZE <= page_size <= self.EVENTS_MAX_PAGE_SIZE
            ):
                raise ValidationError(
                    [
                        {
                            "detail": (
                                f"page[size] must be between {self.EVENTS_MIN_PAGE_SIZE} "
                                f"and {self.EVENTS_MAX_PAGE_SIZE}"
                            ),
                            "status": "400",
                            "source": {"parameter": "page[size]"},
                            "code": "out_of_range",
                        }
                    ]
                )

        # Parse include_read_events (default: false)
        include_read_events = (
            request.query_params.get("include_read_events", "").lower() == "true"
        )

        try:
            # Initialize Prowler provider using existing utility
            prowler_provider = initialize_prowler_provider(resource.provider)

            # Get the boto3 session from the Prowler provider
            session = prowler_provider._session.current_session

            # Create timeline service (currently only AWS/CloudTrail is supported)
            timeline_service = CloudTrailTimeline(
                session=session,
                lookback_days=lookback_days,
                max_results=page_size,
                write_events_only=not include_read_events,
            )

            # Get timeline events
            events = timeline_service.get_resource_timeline(
                region=resource.region,
                resource_uid=resource.uid,
            )

            serializer = ResourceEventSerializer(events, many=True)
            return Response(serializer.data)

        except NoCredentialsError:
            # 502 because this is an upstream auth failure, not API auth failure
            raise UpstreamAuthenticationError(
                detail="Credentials not found for this provider. Please reconnect the provider."
            )
        except AWSAssumeRoleError:
            # AssumeRole failed - usually IAM permission issue (not authorized to sts:AssumeRole)
            raise UpstreamAccessDeniedError(
                detail="Cannot assume role for this provider. Check IAM Role permissions and trust relationship."
            )
        except AWSCredentialsError:
            # Handles expired tokens, invalid keys, profile not found, etc.
            raise UpstreamAuthenticationError()
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            # AccessDenied is expected when credentials lack permissions - don't log as error
            if error_code in ("AccessDenied", "AccessDeniedException"):
                raise UpstreamAccessDeniedError()

            # Unexpected ClientErrors should be logged for debugging
            logger.error(
                f"Provider API error retrieving events: {str(e)}",
                exc_info=True,
            )
            raise UpstreamServiceUnavailableError()
        except Exception as e:
            sentry_sdk.capture_exception(e)
            raise UpstreamInternalError(detail="Failed to retrieve events")


@extend_schema_view(
    list=extend_schema(
        tags=["Finding"],
        summary="List all findings",
        description="Retrieve a list of all findings with options for filtering by various criteria.",
        parameters=[
            OpenApiParameter(
                name="filter[inserted_at]",
                description="At least one of the variations of the `filter[inserted_at]` filter must be provided.",
                required=True,
                type=OpenApiTypes.DATE,
            )
        ],
    ),
    retrieve=extend_schema(
        tags=["Finding"],
        summary="Retrieve data from a specific finding",
        description="Fetch detailed information about a specific finding by its ID.",
    ),
    findings_services_regions=extend_schema(
        tags=["Finding"],
        summary="Retrieve the services and regions that are impacted by findings",
        description="Fetch services and regions affected in findings.",
        filters=True,
        deprecated=True,
    ),
    metadata=extend_schema(
        tags=["Finding"],
        summary="Retrieve metadata values from findings",
        description="Fetch unique metadata values from a set of findings. This is useful for dynamic filtering.",
        parameters=[
            OpenApiParameter(
                name="filter[inserted_at]",
                description="At least one of the variations of the `filter[inserted_at]` filter must be provided.",
                required=True,
                type=OpenApiTypes.DATE,
            )
        ],
        filters=True,
    ),
    latest=extend_schema(
        tags=["Finding"],
        summary="List the latest findings",
        description="Retrieve a list of the latest findings from the latest scans for each provider with options for "
        "filtering by various criteria.",
        filters=True,
    ),
    metadata_latest=extend_schema(
        tags=["Finding"],
        summary="Retrieve metadata values from the latest findings",
        description="Fetch unique metadata values from a set of findings from the latest scans for each provider. "
        "This is useful for dynamic filtering.",
        filters=True,
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class FindingViewSet(PaginateByPkMixin, BaseRLSViewSet):
    queryset = Finding.all_objects.all()
    serializer_class = FindingSerializer
    filterset_class = FindingFilter
    http_method_names = ["get"]
    ordering = ["-inserted_at"]
    ordering_fields = [
        "status",
        "severity",
        "check_id",
        "inserted_at",
        "updated_at",
    ]
    prefetch_for_includes = {
        "__all__": [],
        "resources": [
            Prefetch(
                "resources",
                queryset=Resource.all_objects.prefetch_related("tags", "findings"),
            )
        ],
        "scan": [
            Prefetch("scan", queryset=Scan.all_objects.select_related("findings"))
        ],
    }
    # RBAC required permissions (implicit -> MANAGE_PROVIDERS enable unlimited visibility or check the visibility of
    # the provider through the provider group)
    required_permissions = []

    def get_serializer_class(self):
        if self.action == "findings_services_regions":
            return FindingDynamicFilterSerializer
        elif self.action in ["metadata", "metadata_latest"]:
            return FindingMetadataSerializer

        return super().get_serializer_class()

    def get_filterset_class(self):
        if self.action in ["latest", "metadata_latest"]:
            return LatestFindingFilter
        return FindingFilter

    def get_queryset(self):
        tenant_id = self.request.tenant_id
        user_roles = get_role(self.request.user)
        if user_roles.unlimited_visibility:
            # User has unlimited visibility, return all findings
            queryset = Finding.all_objects.filter(tenant_id=tenant_id)
        else:
            # User lacks permission, filter findings based on provider groups associated with the role
            queryset = Finding.all_objects.filter(
                scan__provider__in=get_providers(user_roles)
            )

        search_value = self.request.query_params.get("filter[search]", None)
        if search_value:
            search_query = SearchQuery(
                search_value, config="simple", search_type="plain"
            )

            queryset = queryset.filter(text_search=search_query)

        return queryset

    def filter_queryset(self, queryset):
        # Do not apply filters when retrieving specific finding
        if self.action == "retrieve":
            return queryset
        return super().filter_queryset(queryset)

    def list(self, request, *args, **kwargs):
        filtered_queryset = self.filter_queryset(self.get_queryset())
        return self.paginate_by_pk(
            request,
            filtered_queryset,
            manager=Finding.all_objects,
            select_related=["scan"],
            prefetch_related=["resources"],
        )

    @action(detail=False, methods=["get"], url_name="findings_services_regions")
    def findings_services_regions(self, request):
        queryset = self.get_queryset()
        filtered_queryset = self.filter_queryset(queryset)

        result = filtered_queryset.aggregate(
            services=ArrayAgg("resources__service", flat=True, distinct=True),
            regions=ArrayAgg("resources__region", flat=True, distinct=True),
        )
        if result["services"] is None:
            result["services"] = []
        if result["regions"] is None:
            result["regions"] = []

        serializer = self.get_serializer(
            data=result,
        )
        serializer.is_valid(raise_exception=True)

        return Response(data=serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_name="metadata")
    def metadata(self, request):
        # Force filter validation
        filtered_queryset = self.filter_queryset(self.get_queryset())

        tenant_id = request.tenant_id
        query_params = request.query_params

        queryset = ResourceScanSummary.objects.filter(tenant_id=tenant_id)
        scan_based_filters = {}
        category_scan_filters = {}  # Filters for ScanCategorySummary

        if scans := query_params.get("filter[scan__in]") or query_params.get(
            "filter[scan]"
        ):
            scan_ids_list = scans.split(",")
            queryset = queryset.filter(scan_id__in=scan_ids_list)
            scan_based_filters = {"id__in": scan_ids_list}
            category_scan_filters = {"scan_id__in": scan_ids_list}
        else:
            exact = query_params.get("filter[inserted_at]")
            gte = query_params.get("filter[inserted_at__gte]")
            lte = query_params.get("filter[inserted_at__lte]")

            date_filters = {}
            if exact:
                date = parse_date(exact)
                datetime_start = datetime.combine(
                    date, datetime.min.time(), tzinfo=timezone.utc
                )
                datetime_end = datetime_start + timedelta(days=1)
                date_filters["scan_id__gte"] = uuid7_start(
                    datetime_to_uuid7(datetime_start)
                )
                date_filters["scan_id__lt"] = uuid7_start(
                    datetime_to_uuid7(datetime_end)
                )
            else:
                if gte:
                    date_start = parse_date(gte)
                    datetime_start = datetime.combine(
                        date_start, datetime.min.time(), tzinfo=timezone.utc
                    )
                    date_filters["scan_id__gte"] = uuid7_start(
                        datetime_to_uuid7(datetime_start)
                    )
                if lte:
                    date_end = parse_date(lte)
                    datetime_end = datetime.combine(
                        date_end + timedelta(days=1),
                        datetime.min.time(),
                        tzinfo=timezone.utc,
                    )
                    date_filters["scan_id__lt"] = uuid7_start(
                        datetime_to_uuid7(datetime_end)
                    )

            if date_filters:
                queryset = queryset.filter(**date_filters)
                scan_based_filters = {
                    key.lstrip("scan_"): value for key, value in date_filters.items()
                }
                category_scan_filters = date_filters

        # ToRemove: Temporary fallback mechanism
        if not queryset.exists():
            raw_scans_ids = Scan.objects.filter(
                tenant_id=tenant_id, **scan_based_filters
            ).values_list("id", "unique_resource_count")
            scan_ids = [
                scan_id for scan_id, count in raw_scans_ids if count and count > 0
            ]
            for scan_id in scan_ids:
                backfill_scan_resource_summaries_task.apply_async(
                    kwargs={"tenant_id": tenant_id, "scan_id": scan_id}
                )
            return Response(
                get_findings_metadata_no_aggregations(tenant_id, filtered_queryset)
            )

        if service_filter := query_params.get("filter[service]") or query_params.get(
            "filter[service__in]"
        ):
            queryset = queryset.filter(service__in=service_filter.split(","))
        if region_filter := query_params.get("filter[region]") or query_params.get(
            "filter[region__in]"
        ):
            queryset = queryset.filter(region__in=region_filter.split(","))
        if resource_type_filter := query_params.get(
            "filter[resource_type]"
        ) or query_params.get("filter[resource_type__in]"):
            queryset = queryset.filter(
                resource_type__in=resource_type_filter.split(",")
            )

        services = list(
            queryset.values_list("service", flat=True).distinct().order_by("service")
        )
        regions = list(
            queryset.values_list("region", flat=True).distinct().order_by("region")
        )
        resource_types = list(
            queryset.values_list("resource_type", flat=True)
            .exclude(resource_type__isnull=True)
            .exclude(resource_type__exact="")
            .distinct()
            .order_by("resource_type")
        )

        # Get categories from ScanCategorySummary using same scan filters
        categories = list(
            ScanCategorySummary.objects.filter(
                tenant_id=tenant_id, **category_scan_filters
            )
            .values_list("category", flat=True)
            .distinct()
            .order_by("category")
        )

        # Fallback to finding aggregation if no ScanCategorySummary exists
        if not categories:
            categories_set = set()
            for categories_list in filtered_queryset.values_list(
                "categories", flat=True
            ):
                if categories_list:
                    categories_set.update(categories_list)
            categories = sorted(categories_set)

        result = {
            "services": services,
            "regions": regions,
            "resource_types": resource_types,
            "categories": categories,
        }

        serializer = self.get_serializer(data=result)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], url_name="latest")
    def latest(self, request):
        tenant_id = request.tenant_id
        filtered_queryset = self.filter_queryset(self.get_queryset())

        latest_scan_ids = (
            Scan.all_objects.filter(tenant_id=tenant_id, state=StateChoices.COMPLETED)
            .order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
            .values_list("id", flat=True)
        )
        filtered_queryset = filtered_queryset.filter(
            tenant_id=tenant_id, scan_id__in=latest_scan_ids
        )

        return self.paginate_by_pk(
            request,
            filtered_queryset,
            manager=Finding.all_objects,
            select_related=["scan"],
            prefetch_related=["resources"],
        )

    @action(
        detail=False,
        methods=["get"],
        url_name="metadata_latest",
        url_path="metadata/latest",
    )
    def metadata_latest(self, request):
        tenant_id = request.tenant_id
        query_params = request.query_params

        latest_scans_queryset = (
            Scan.all_objects.filter(tenant_id=tenant_id, state=StateChoices.COMPLETED)
            .order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
        )
        raw_latest_scans_ids = list(
            latest_scans_queryset.values_list("id", "unique_resource_count")
        )
        latest_scans_ids = [
            scan_id for scan_id, count in raw_latest_scans_ids if count and count > 0
        ]

        queryset = ResourceScanSummary.objects.filter(
            tenant_id=tenant_id,
            scan_id__in=latest_scans_queryset.values_list("id", flat=True),
        )
        # ToRemove: Temporary fallback mechanism
        present_ids = set(
            ResourceScanSummary.objects.filter(
                tenant_id=tenant_id, scan_id__in=latest_scans_ids
            )
            .values_list("scan_id", flat=True)
            .distinct()
        )
        missing_scan_ids = [sid for sid in latest_scans_ids if sid not in present_ids]
        if missing_scan_ids:
            for scan_id in missing_scan_ids:
                backfill_scan_resource_summaries_task.apply_async(
                    kwargs={"tenant_id": tenant_id, "scan_id": scan_id}
                )
            return Response(
                get_findings_metadata_no_aggregations(
                    tenant_id, self.filter_queryset(self.get_queryset())
                )
            )

        if service_filter := query_params.get("filter[service]") or query_params.get(
            "filter[service__in]"
        ):
            queryset = queryset.filter(service__in=service_filter.split(","))
        if region_filter := query_params.get("filter[region]") or query_params.get(
            "filter[region__in]"
        ):
            queryset = queryset.filter(region__in=region_filter.split(","))
        if resource_type_filter := query_params.get(
            "filter[resource_type]"
        ) or query_params.get("filter[resource_type__in]"):
            queryset = queryset.filter(
                resource_type__in=resource_type_filter.split(",")
            )

        services = list(
            queryset.values_list("service", flat=True).distinct().order_by("service")
        )
        regions = list(
            queryset.values_list("region", flat=True).distinct().order_by("region")
        )
        resource_types = list(
            queryset.values_list("resource_type", flat=True)
            .exclude(resource_type__isnull=True)
            .exclude(resource_type__exact="")
            .distinct()
            .order_by("resource_type")
        )

        # Get categories from ScanCategorySummary for latest scans
        categories = list(
            ScanCategorySummary.objects.filter(
                tenant_id=tenant_id,
                scan_id__in=latest_scans_queryset.values_list("id", flat=True),
            )
            .values_list("category", flat=True)
            .distinct()
            .order_by("category")
        )

        # Fallback to finding aggregation if no ScanCategorySummary exists
        if not categories:
            filtered_queryset = self.filter_queryset(self.get_queryset()).filter(
                tenant_id=tenant_id,
                scan_id__in=latest_scans_queryset.values_list("id", flat=True),
            )
            categories_set = set()
            for categories_list in filtered_queryset.values_list(
                "categories", flat=True
            ):
                if categories_list:
                    categories_set.update(categories_list)
            categories = sorted(categories_set)

        # Get groups from ScanGroupSummary for latest scans
        groups = list(
            ScanGroupSummary.objects.filter(
                tenant_id=tenant_id,
                scan_id__in=latest_scans_queryset.values_list("id", flat=True),
            )
            .values_list("resource_group", flat=True)
            .distinct()
            .order_by("resource_group")
        )

        result = {
            "services": services,
            "regions": regions,
            "resource_types": resource_types,
            "categories": categories,
            "groups": groups,
        }

        serializer = self.get_serializer(data=result)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)


@extend_schema_view(
    list=extend_schema(
        tags=["Provider"],
        summary="List all secrets",
        description="Retrieve a list of all secrets with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        tags=["Provider"],
        summary="Retrieve data from a secret",
        description="Fetch detailed information about a specific secret by their ID.",
    ),
    create=extend_schema(
        tags=["Provider"],
        summary="Create a new secret",
        description="Add a new secret to the system by providing the required secret details.",
    ),
    partial_update=extend_schema(
        tags=["Provider"],
        summary="Partially update a secret",
        description="Update certain fields of an existing secret's information without affecting other fields.",
    ),
    destroy=extend_schema(
        tags=["Provider"],
        summary="Delete a secret",
        description="Remove a secret from the system by their ID.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ProviderSecretViewSet(BaseRLSViewSet):
    queryset = ProviderSecret.objects.all()
    serializer_class = ProviderSecretSerializer
    filterset_class = ProviderSecretFilter
    http_method_names = ["get", "post", "patch", "delete"]
    search_fields = ["name"]
    ordering = ["-inserted_at"]
    ordering_fields = [
        "name",
        "inserted_at",
        "updated_at",
    ]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_PROVIDERS]

    def get_queryset(self):
        return ProviderSecret.objects.filter(tenant_id=self.request.tenant_id)

    def get_serializer_class(self):
        if self.action == "create":
            return ProviderSecretCreateSerializer
        elif self.action == "partial_update":
            return ProviderSecretUpdateSerializer
        return super().get_serializer_class()


@extend_schema_view(
    list=extend_schema(
        tags=["Invitation"],
        summary="List all invitations",
        description="Retrieve a list of all tenant invitations with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        tags=["Invitation"],
        summary="Retrieve data from a tenant invitation",
        description="Fetch detailed information about a specific invitation by its ID.",
    ),
    create=extend_schema(
        tags=["Invitation"],
        summary="Invite a user to a tenant",
        description="Add a new tenant invitation to the system by providing the required invitation details. The "
        "invited user will have to accept the invitations or create an account using the given code.",
    ),
    partial_update=extend_schema(
        tags=["Invitation"],
        summary="Partially update a tenant invitation",
        description="Update certain fields of an existing tenant invitation's information without affecting other "
        "fields.",
    ),
    destroy=extend_schema(
        tags=["Invitation"],
        summary="Revoke a tenant invitation",
        description="Revoke a tenant invitation from the system by their ID.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class InvitationViewSet(BaseRLSViewSet):
    queryset = Invitation.objects.all()
    serializer_class = InvitationSerializer
    filterset_class = InvitationFilter
    http_method_names = ["get", "post", "patch", "delete"]
    search_fields = ["email"]
    ordering = ["-inserted_at"]
    ordering_fields = [
        "inserted_at",
        "updated_at",
        "expires_at",
        "state",
        "inviter",
    ]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_ACCOUNT]

    def get_queryset(self):
        return Invitation.objects.filter(tenant_id=self.request.tenant_id)

    def get_serializer_class(self):
        if self.action == "create":
            return InvitationCreateSerializer
        elif self.action == "partial_update":
            return InvitationUpdateSerializer
        return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data,
            context={"tenant_id": self.request.tenant_id, "request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.state != Invitation.State.PENDING:
            raise ValidationError(detail="This invitation cannot be updated.")
        serializer = self.get_serializer(
            instance,
            data=request.data,
            partial=True,
            context={"tenant_id": self.request.tenant_id, "request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(data=serializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.state != Invitation.State.PENDING:
            raise ValidationError(detail="This invitation cannot be revoked.")
        instance.state = Invitation.State.REVOKED
        instance.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class InvitationAcceptViewSet(BaseRLSViewSet):
    queryset = Invitation.objects.all()
    serializer_class = InvitationAcceptSerializer
    http_method_names = ["post"]

    def get_queryset(self):
        return Invitation.objects.filter(tenant_id=self.request.tenant_id)

    def get_serializer_class(self):
        if hasattr(self, "response_serializer_class"):
            return self.response_serializer_class
        return InvitationAcceptSerializer

    @extend_schema(exclude=True)
    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="POST")

    @extend_schema(
        tags=["Invitation"],
        summary="Accept an invitation",
        description="Accept an invitation to an existing tenant. This invitation cannot be expired and the emails must "
        "match.",
        responses={201: OpenApiResponse(response=MembershipSerializer)},
    )
    @action(detail=False, methods=["post"], url_name="accept")
    def accept(self, request):
        serializer = self.get_serializer(
            data=request.data,
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)
        invitation_token = serializer.validated_data["invitation_token"]
        user_email = request.user.email

        invitation = validate_invitation(
            invitation_token, user_email, raise_not_found=True
        )

        # Proceed with accepting the invitation
        user = User.objects.using(MainRouter.admin_db).get(email=user_email)
        membership = Membership.objects.using(MainRouter.admin_db).create(
            user=user,
            tenant=invitation.tenant,
        )
        user_role = []
        for role in invitation.roles.all():
            user_role.append(
                UserRoleRelationship.objects.using(MainRouter.admin_db).create(
                    user=user, role=role, tenant=invitation.tenant
                )
            )
        invitation.state = Invitation.State.ACCEPTED
        invitation.save(using=MainRouter.admin_db)

        self.response_serializer_class = MembershipSerializer
        membership_serializer = self.get_serializer(membership)
        return Response(data=membership_serializer.data, status=status.HTTP_201_CREATED)


@extend_schema(tags=["Role"])
@extend_schema_view(
    list=extend_schema(
        tags=["Role"],
        summary="List all roles",
        description="Retrieve a list of all roles with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        tags=["Role"],
        summary="Retrieve data from a role",
        description="Fetch detailed information about a specific role by their ID.",
    ),
    create=extend_schema(
        tags=["Role"],
        summary="Create a new role",
        description="Add a new role to the system by providing the required role details.",
    ),
    partial_update=extend_schema(
        tags=["Role"],
        summary="Partially update a role",
        responses={200: RoleSerializer},
    ),
    destroy=extend_schema(
        tags=["Role"],
        summary="Delete a role",
    ),
)
class RoleViewSet(BaseRLSViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    filterset_class = RoleFilter
    http_method_names = ["get", "post", "patch", "delete"]
    ordering = ["inserted_at"]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_ACCOUNT]

    def get_queryset(self):
        return Role.objects.filter(tenant_id=self.request.tenant_id)

    def get_serializer_class(self):
        if self.action == "create":
            return RoleCreateSerializer
        elif self.action == "partial_update":
            return RoleUpdateSerializer
        return super().get_serializer_class()

    @extend_schema(
        description=(
            "Update selected fields on an existing role. When changing the `users` "
            "relationship of a role that grants MANAGE_ACCOUNT, the API blocks attempts "
            "that would leave the tenant without any MANAGE_ACCOUNT assignees and prevents "
            "callers from removing their own assignment to that role."
        )
    )
    def partial_update(self, request, *args, **kwargs):
        user_role = get_role(request.user)
        # If the user is the owner of the role, the manage_account field is not editable
        if user_role and kwargs["pk"] == str(user_role.id):
            request.data["manage_account"] = str(user_role.manage_account).lower()
        return super().partial_update(request, *args, **kwargs)

    @extend_schema(
        description=(
            "Delete the specified role. The API rejects deletion of the last role "
            "in the tenant that grants MANAGE_ACCOUNT."
        )
    )
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if (
            instance.name == "admin"
        ):  # TODO: Move to a constant/enum (in case other roles are created by default)
            raise ValidationError(detail="The admin role cannot be deleted.")

        # Prevent deleting the last MANAGE_ACCOUNT role in the tenant
        if instance.manage_account:
            has_other_ma = (
                Role.objects.filter(tenant_id=instance.tenant_id, manage_account=True)
                .exclude(id=instance.id)
                .exists()
            )
            if not has_other_ma:
                return Response(
                    data={
                        "detail": "Cannot delete the only role with MANAGE_ACCOUNT in the tenant."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return super().destroy(request, *args, **kwargs)


@extend_schema_view(
    create=extend_schema(
        tags=["Role"],
        summary="Create a new role-provider_groups relationship",
        description="Add a new role-provider_groups relationship to the system by providing the required "
        "role-provider_groups details.",
        responses={
            204: OpenApiResponse(description="Relationship created successfully"),
            400: OpenApiResponse(
                description="Bad request (e.g., relationship already exists)"
            ),
        },
    ),
    partial_update=extend_schema(
        tags=["Role"],
        summary="Partially update a role-provider_groups relationship",
        description="Update the role-provider_groups relationship information without affecting other fields.",
        responses={
            204: OpenApiResponse(
                response=None, description="Relationship updated successfully"
            )
        },
    ),
    destroy=extend_schema(
        tags=["Role"],
        summary="Delete a role-provider_groups relationship",
        description="Remove the role-provider_groups relationship from the system by their ID.",
        responses={
            204: OpenApiResponse(
                response=None, description="Relationship deleted successfully"
            )
        },
    ),
)
class RoleProviderGroupRelationshipView(RelationshipView, BaseRLSViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleProviderGroupRelationshipSerializer
    resource_name = "provider_groups"
    http_method_names = ["post", "patch", "delete"]
    schema = RelationshipViewSchema()
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_ACCOUNT]

    def get_queryset(self):
        return Role.objects.filter(tenant_id=self.request.tenant_id)

    def create(self, request, *args, **kwargs):
        role = self.get_object()

        provider_group_ids = [item["id"] for item in request.data]
        existing_relationships = RoleProviderGroupRelationship.objects.filter(
            role=role, provider_group_id__in=provider_group_ids
        )

        if existing_relationships.exists():
            return Response(
                {
                    "detail": "One or more provider groups are already associated with the role."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = self.get_serializer(
            data={"provider_groups": request.data},
            context={
                "role": role,
                "tenant_id": self.request.tenant_id,
                "request": request,
            },
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)

    def partial_update(self, request, *args, **kwargs):
        role = self.get_object()
        serializer = self.get_serializer(
            instance=role,
            data={"provider_groups": request.data},
            context={"tenant_id": self.request.tenant_id, "request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def destroy(self, request, *args, **kwargs):
        role = self.get_object()
        role.provider_groups.clear()

        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    list=extend_schema(
        tags=["Compliance Overview"],
        summary="List compliance overviews for a scan",
        description="Retrieve an overview of all the compliance in a given scan.",
        parameters=[
            OpenApiParameter(
                name="filter[scan_id]",
                required=True,
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.QUERY,
                description="Related scan ID.",
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="Compliance overviews obtained successfully",
                response=ComplianceOverviewSerializer(many=True),
            ),
            202: OpenApiResponse(
                description="The task is in progress", response=TaskSerializer
            ),
            500: OpenApiResponse(
                description="Compliance overviews generation task failed"
            ),
        },
    ),
    metadata=extend_schema(
        tags=["Compliance Overview"],
        summary="Retrieve metadata values from compliance overviews",
        description="Fetch unique metadata values from a set of compliance overviews. This is useful for dynamic "
        "filtering.",
        parameters=[
            OpenApiParameter(
                name="filter[scan_id]",
                required=True,
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.QUERY,
                description="Related scan ID.",
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="Compliance overviews metadata obtained successfully",
                response=ComplianceOverviewMetadataSerializer,
            ),
            202: OpenApiResponse(
                description="The task is in progress", response=TaskSerializer
            ),
            500: OpenApiResponse(
                description="Compliance overviews generation task failed"
            ),
        },
    ),
    requirements=extend_schema(
        tags=["Compliance Overview"],
        summary="List compliance requirements overview for a scan",
        description="Retrieve a detailed overview of compliance requirements in a given scan, grouped by compliance "
        "framework. This endpoint provides requirement-level details and aggregates status across regions.",
        parameters=[
            OpenApiParameter(
                name="filter[scan_id]",
                required=True,
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.QUERY,
                description="Related scan ID.",
            ),
            OpenApiParameter(
                name="filter[compliance_id]",
                required=True,
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Compliance ID.",
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="Compliance requirement details obtained successfully",
                response=ComplianceOverviewDetailSerializer(many=True),
            ),
            202: OpenApiResponse(
                description="The task is in progress", response=TaskSerializer
            ),
            500: OpenApiResponse(
                description="Compliance overviews generation task failed"
            ),
        },
        filters=True,
    ),
    attributes=extend_schema(
        tags=["Compliance Overview"],
        summary="Get compliance requirement attributes",
        description="Retrieve detailed attribute information for all requirements in a specific compliance framework "
        "along with the associated check IDs for each requirement.",
        parameters=[
            OpenApiParameter(
                name="filter[compliance_id]",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
                description="Compliance framework ID to get attributes for.",
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="Compliance attributes obtained successfully",
                response=ComplianceOverviewAttributesSerializer(many=True),
            ),
        },
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="requirements")
@method_decorator(CACHE_DECORATOR, name="attributes")
class ComplianceOverviewViewSet(BaseRLSViewSet, TaskManagementMixin):
    pagination_class = ComplianceOverviewPagination
    queryset = ComplianceRequirementOverview.objects.all()
    serializer_class = ComplianceOverviewSerializer
    filterset_class = ComplianceOverviewFilter
    http_method_names = ["get"]
    search_fields = ["compliance_id"]
    ordering = ["compliance_id"]
    ordering_fields = ["compliance_id"]
    # RBAC required permissions (implicit -> MANAGE_PROVIDERS enable unlimited visibility or check the visibility of
    # the provider through the provider group)
    required_permissions = []

    def get_queryset(self):
        role = get_role(self.request.user)
        unlimited_visibility = getattr(
            role, Permissions.UNLIMITED_VISIBILITY.value, False
        )

        if unlimited_visibility:
            base_queryset = self.filter_queryset(
                ComplianceRequirementOverview.objects.filter(
                    tenant_id=self.request.tenant_id
                )
            )
        else:
            providers = Provider.objects.filter(
                provider_groups__in=role.provider_groups.all()
            ).distinct()
            base_queryset = self.filter_queryset(
                ComplianceRequirementOverview.objects.filter(
                    tenant_id=self.request.tenant_id, scan__provider__in=providers
                )
            )

        return base_queryset

    def get_serializer_class(self):
        if hasattr(self, "response_serializer_class"):
            return self.response_serializer_class
        elif self.action == "list":
            return ComplianceOverviewSerializer
        elif self.action == "metadata":
            return ComplianceOverviewMetadataSerializer
        elif self.action == "attributes":
            return ComplianceOverviewAttributesSerializer
        elif self.action == "requirements":
            return ComplianceOverviewDetailSerializer
        return super().get_serializer_class()

    @extend_schema(exclude=True)
    def retrieve(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="GET")

    def _compliance_summaries_queryset(self, scan_id):
        """Return pre-aggregated summaries constrained by RBAC visibility."""
        role = get_role(self.request.user)
        unlimited_visibility = getattr(
            role, Permissions.UNLIMITED_VISIBILITY.value, False
        )
        summaries = ComplianceOverviewSummary.objects.filter(
            tenant_id=self.request.tenant_id,
            scan_id=scan_id,
        )

        if not unlimited_visibility:
            providers = Provider.all_objects.filter(
                provider_groups__in=role.provider_groups.all()
            ).distinct()
            summaries = summaries.filter(scan__provider__in=providers)

        return summaries

    def _get_compliance_template(self, *, provider=None, scan_id=None):
        """Return the compliance template for the given provider or scan."""
        if provider is None and scan_id is not None:
            try:
                scan = Scan.all_objects.select_related("provider").get(pk=scan_id)
            except Scan.DoesNotExist:
                raise ValidationError(
                    [
                        {
                            "detail": "Scan not found",
                            "status": 404,
                            "source": {"pointer": "filter[scan_id]"},
                            "code": "not_found",
                        }
                    ]
                )
            provider = scan.provider

        if not provider:
            return {}

        return PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE.get(provider.provider, {})

    def _aggregate_compliance_overview(self, queryset, template_metadata=None):
        """
        Aggregate requirement rows into compliance overview dictionaries.

        Args:
            queryset: ComplianceRequirementOverview queryset already filtered.
            template_metadata: Optional dict mapping compliance_id -> metadata.
        """
        template_metadata = template_metadata or {}
        requirement_status_subquery = queryset.values(
            "compliance_id", "requirement_id"
        ).annotate(
            fail_count=Count("id", filter=Q(requirement_status="FAIL")),
            pass_count=Count("id", filter=Q(requirement_status="PASS")),
            total_count=Count("id"),
        )

        compliance_data = {}
        fallback_metadata = {
            item["compliance_id"]: {
                "framework": item["framework"],
                "version": item["version"],
            }
            for item in queryset.values(
                "compliance_id", "framework", "version"
            ).distinct()
        }

        for item in requirement_status_subquery:
            compliance_id = item["compliance_id"]

            if item["fail_count"] > 0:
                req_status = "FAIL"
            elif item["pass_count"] == item["total_count"]:
                req_status = "PASS"
            else:
                req_status = "MANUAL"

            compliance_status = compliance_data.setdefault(
                compliance_id,
                {
                    "total_requirements": 0,
                    "requirements_passed": 0,
                    "requirements_failed": 0,
                    "requirements_manual": 0,
                },
            )

            compliance_status["total_requirements"] += 1
            if req_status == "PASS":
                compliance_status["requirements_passed"] += 1
            elif req_status == "FAIL":
                compliance_status["requirements_failed"] += 1
            else:
                compliance_status["requirements_manual"] += 1

        response_data = []
        for compliance_id, data in compliance_data.items():
            template = template_metadata.get(compliance_id, {})
            fallback = fallback_metadata.get(compliance_id, {})

            response_data.append(
                {
                    "id": compliance_id,
                    "compliance_id": compliance_id,
                    "framework": template.get("framework")
                    or fallback.get("framework", ""),
                    "version": template.get("version") or fallback.get("version", ""),
                    "requirements_passed": data["requirements_passed"],
                    "requirements_failed": data["requirements_failed"],
                    "requirements_manual": data["requirements_manual"],
                    "total_requirements": data["total_requirements"],
                }
            )

        serializer = self.get_serializer(response_data, many=True)
        return serializer.data

    def _task_response_if_running(self, scan_id):
        """Check for an in-progress task only when no compliance data exists."""
        try:
            return self.get_task_response_if_running(
                task_name="scan-compliance-overviews",
                task_kwargs={"tenant_id": self.request.tenant_id, "scan_id": scan_id},
                raise_on_not_found=False,
            )
        except TaskFailedException:
            return Response(
                {"detail": "Task failed to generate compliance overview data."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _list_with_region_filter(self, scan_id, region_filter):
        """
        Fall back to detailed ComplianceRequirementOverview query when region filter is applied.
        This uses the original aggregation logic across filtered regions.
        """
        regions = region_filter.split(",") if "," in region_filter else [region_filter]
        queryset = self.filter_queryset(self.get_queryset()).filter(
            scan_id=scan_id,
            region__in=regions,
        )

        data = self._aggregate_compliance_overview(queryset)
        if data:
            return Response(data)

        task_response = self._task_response_if_running(scan_id)
        if task_response:
            return task_response

        return Response(data)

    def _list_without_region_aggregation(self, scan_id):
        """
        Fall back aggregation when compliance summaries don't exist yet.
        Aggregates ComplianceRequirementOverview data across ALL regions.
        """
        queryset = self.filter_queryset(self.get_queryset()).filter(scan_id=scan_id)
        compliance_template = self._get_compliance_template(scan_id=scan_id)
        data = self._aggregate_compliance_overview(
            queryset, template_metadata=compliance_template
        )
        if data:
            return Response(data)

        task_response = self._task_response_if_running(scan_id)
        if task_response:
            return task_response

        return Response(data)

    def list(self, request, *args, **kwargs):
        scan_id = request.query_params.get("filter[scan_id]")

        # Specific scan requested - use optimized summaries with region support
        region_filter = request.query_params.get(
            "filter[region]"
        ) or request.query_params.get("filter[region__in]")

        if region_filter:
            # Fall back to detailed query with region filtering
            return self._list_with_region_filter(scan_id, region_filter)

        summaries = list(self._compliance_summaries_queryset(scan_id))
        if not summaries:
            # Trigger async backfill for next time
            backfill_compliance_summaries_task.delay(
                tenant_id=self.request.tenant_id, scan_id=scan_id
            )
            # Use fallback aggregation for this request
            return self._list_without_region_aggregation(scan_id)

        # Get compliance template for provider to enrich with framework/version
        compliance_template = self._get_compliance_template(scan_id=scan_id)

        # Convert to response format with framework/version enrichment
        response_data = []
        for summary in summaries:
            compliance_metadata = compliance_template.get(summary.compliance_id, {})
            response_data.append(
                {
                    "id": summary.compliance_id,
                    "compliance_id": summary.compliance_id,
                    "framework": compliance_metadata.get("framework", ""),
                    "version": compliance_metadata.get("version", ""),
                    "requirements_passed": summary.requirements_passed,
                    "requirements_failed": summary.requirements_failed,
                    "requirements_manual": summary.requirements_manual,
                    "total_requirements": summary.total_requirements,
                }
            )

        serializer = self.get_serializer(response_data, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], url_name="metadata")
    def metadata(self, request):
        scan_id = request.query_params.get("filter[scan_id]")
        if not scan_id:
            raise ValidationError(
                [
                    {
                        "detail": "This query parameter is required.",
                        "status": 400,
                        "source": {"pointer": "filter[scan_id]"},
                        "code": "required",
                    }
                ]
            )
        regions = list(
            self.get_queryset()
            .filter(scan_id=scan_id)
            .values_list("region", flat=True)
            .order_by("region")
            .distinct()
        )
        result = {"regions": regions}

        if regions:
            serializer = self.get_serializer(data=result)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        task_response = self._task_response_if_running(scan_id)
        if task_response:
            return task_response

        serializer = self.get_serializer(data=result)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_name="requirements")
    def requirements(self, request):
        scan_id = request.query_params.get("filter[scan_id]")
        compliance_id = request.query_params.get("filter[compliance_id]")

        if not scan_id:
            raise ValidationError(
                [
                    {
                        "detail": "This query parameter is required.",
                        "status": 400,
                        "source": {"pointer": "filter[scan_id]"},
                        "code": "required",
                    }
                ]
            )

        if not compliance_id:
            raise ValidationError(
                [
                    {
                        "detail": "This query parameter is required.",
                        "status": 400,
                        "source": {"pointer": "filter[compliance_id]"},
                        "code": "required",
                    }
                ]
            )
        filtered_queryset = self.filter_queryset(self.get_queryset())

        all_requirements = filtered_queryset.values(
            "requirement_id",
            "framework",
            "version",
            "description",
        ).annotate(
            total_instances=Count("id"),
            manual_count=Count("id", filter=Q(requirement_status="MANUAL")),
            passed_findings_sum=Sum("passed_findings"),
            total_findings_sum=Sum("total_findings"),
        )

        passed_instances = (
            filtered_queryset.filter(requirement_status="PASS")
            .values("requirement_id")
            .annotate(pass_count=Count("id"))
        )

        passed_counts = {
            item["requirement_id"]: item["pass_count"] for item in passed_instances
        }

        requirements_summary = []
        for requirement in all_requirements:
            requirement_id = requirement["requirement_id"]
            total_instances = requirement["total_instances"]
            passed_count = passed_counts.get(requirement_id, 0)
            is_manual = requirement["manual_count"] == total_instances
            passed_findings = requirement["passed_findings_sum"] or 0
            total_findings = requirement["total_findings_sum"] or 0
            if is_manual:
                requirement_status = "MANUAL"
            elif passed_count == total_instances:
                requirement_status = "PASS"
            else:
                requirement_status = "FAIL"

            requirements_summary.append(
                {
                    "id": requirement_id,
                    "framework": requirement["framework"],
                    "version": requirement["version"],
                    "description": requirement["description"],
                    "status": requirement_status,
                    "passed_findings": passed_findings,
                    "total_findings": total_findings,
                }
            )

        # Use different serializer for threatscore framework
        if "threatscore" not in compliance_id:
            serializer = self.get_serializer(requirements_summary, many=True)
        else:
            serializer = ComplianceOverviewDetailThreatscoreSerializer(
                requirements_summary, many=True
            )

        if requirements_summary:
            return Response(serializer.data, status=status.HTTP_200_OK)

        task_response = self._task_response_if_running(scan_id)
        if task_response:
            return task_response

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_name="attributes")
    def attributes(self, request):
        compliance_id = request.query_params.get("filter[compliance_id]")
        if not compliance_id:
            raise ValidationError(
                [
                    {
                        "detail": "This query parameter is required.",
                        "status": 400,
                        "source": {"pointer": "filter[compliance_id]"},
                        "code": "required",
                    }
                ]
            )

        provider_type = None

        # If we couldn't determine from database, try each provider type
        if not provider_type:
            for pt in Provider.ProviderChoices.values:
                if compliance_id in get_compliance_frameworks(pt):
                    provider_type = pt
                    break

        if not provider_type:
            raise NotFound(detail=f"Compliance framework '{compliance_id}' not found.")

        compliance_template = PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE.get(
            provider_type, {}
        )
        compliance_framework = compliance_template.get(compliance_id)

        if not compliance_framework:
            raise NotFound(detail=f"Compliance framework '{compliance_id}' not found.")

        attribute_data = []
        for requirement_id, requirement in compliance_framework.get(
            "requirements", {}
        ).items():
            check_ids = list(requirement.get("checks", {}).keys())

            metadata = requirement.get("attributes", [])

            base_attributes = {
                "metadata": metadata,
                "check_ids": check_ids,
            }

            # Add technique details for MITRE-ATTACK framework
            if "mitre_attack" in compliance_id:
                base_attributes["technique_details"] = {
                    "tactics": requirement.get("tactics", []),
                    "subtechniques": requirement.get("subtechniques", []),
                    "platforms": requirement.get("platforms", []),
                    "technique_url": requirement.get("technique_url", ""),
                }

            attribute_data.append(
                {
                    "id": requirement_id,
                    "framework_description": compliance_framework.get(
                        "description", ""
                    ),
                    "name": requirement.get("name", ""),
                    "framework": compliance_framework.get("framework", ""),
                    "compliance_name": compliance_framework.get("name", ""),
                    "version": compliance_framework.get("version", ""),
                    "description": requirement.get("description", ""),
                    "attributes": base_attributes,
                }
            )

        serializer = self.get_serializer(attribute_data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


@extend_schema(tags=["Overview"])
@extend_schema_view(
    providers=extend_schema(
        summary="Get aggregated provider data",
        description=(
            "Retrieve an aggregated overview of findings and resources grouped by providers. "
            "The response includes the count of passed, failed, and manual findings, along with "
            "the total number of resources managed by each provider. Only the latest findings for "
            "each provider are considered in the aggregation to ensure accurate and up-to-date insights."
        ),
    ),
    providers_count=extend_schema(
        summary="Get provider counts grouped by type",
        description=(
            "Retrieve the number of providers grouped by provider type. "
            "This endpoint counts every provider in the tenant, including those without completed scans."
        ),
    ),
    findings=extend_schema(
        summary="Get aggregated findings data",
        description=(
            "Fetch aggregated findings data across all providers, grouped by various metrics such as "
            "passed, failed, muted, and total findings. This endpoint calculates summary statistics "
            "based on the latest scans for each provider and applies any provided filters, such as "
            "region, provider type, and scan date."
        ),
        filters=True,
    ),
    findings_severity=extend_schema(
        summary="Get findings data by severity",
        description=(
            "Retrieve an aggregated summary of findings grouped by severity levels, such as low, medium, "
            "high, and critical. The response includes the total count of findings for each severity, "
            "considering only the latest scans for each provider. Additional filters can be applied to "
            "narrow down results by region, provider type, or other attributes."
        ),
        filters=True,
    ),
    services=extend_schema(
        summary="Get findings data by service",
        description=(
            "Retrieve an aggregated summary of findings grouped by service. The response includes the total count "
            "of findings for each service, as long as there are at least one finding for that service."
        ),
        filters=True,
    ),
    regions=extend_schema(
        summary="Get findings data by region",
        description=(
            "Retrieve an aggregated summary of findings grouped by region. The response includes the total, passed, "
            "failed, and muted findings for each region based on the latest completed scans per provider. "
            "Standard overview filters (inserted_at, provider filters, region filters, etc.) are supported."
        ),
        filters=True,
    ),
    findings_severity_timeseries=extend_schema(
        summary="Get findings severity data over time",
        description=(
            "Retrieve daily aggregated findings data grouped by severity levels over a date range. "
            "Returns one data point per day with counts of failed findings by severity (critical, high, "
            "medium, low, informational) and muted findings. Days without scans are filled forward with "
            "the most recent known values. Use date_from (required) and date_to filters to specify the range."
        ),
        filters=True,
    ),
    attack_surface=extend_schema(
        summary="Get attack surface overview",
        description="Retrieve aggregated attack surface metrics from latest completed scans per provider.",
        tags=["Overview"],
        filters=True,
        responses={200: AttackSurfaceOverviewSerializer(many=True)},
    ),
    categories=extend_schema(
        summary="Get category overview",
        description=(
            "Retrieve aggregated category metrics from latest completed scans per provider. "
            "Returns one row per category with total, failed, and new failed findings counts, "
            "plus a severity breakdown showing failed findings per severity level. "
        ),
        tags=["Overview"],
        filters=True,
        responses={200: CategoryOverviewSerializer(many=True)},
    ),
    resource_groups=extend_schema(
        summary="Get resource group overview",
        description=(
            "Retrieve aggregated resource group metrics from latest completed scans per provider. "
            "Returns one row per resource group with total, failed, and new failed findings counts, "
            "plus a severity breakdown showing failed findings per severity level, "
            "and a count of distinct resources evaluated per group."
        ),
        tags=["Overview"],
        filters=True,
        responses={200: ResourceGroupOverviewSerializer(many=True)},
    ),
    compliance_watchlist=extend_schema(
        summary="Get compliance watchlist overview",
        description=(
            "Retrieve compliance metrics with FAIL-dominant aggregation. "
            "Without filters: uses pre-aggregated TenantComplianceSummary. "
            "With provider filters: queries ProviderComplianceScore with FAIL-dominant logic "
            "where any FAIL in a requirement marks it as failed."
        ),
        tags=["Overview"],
        filters=True,
        responses={200: ComplianceWatchlistOverviewSerializer(many=True)},
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
class OverviewViewSet(BaseRLSViewSet):
    queryset = ScanSummary.objects.all()
    http_method_names = ["get"]
    ordering = ["-inserted_at"]
    # RBAC required permissions (implicit -> MANAGE_PROVIDERS enable unlimited visibility or check the visibility of
    # the provider through the provider group)
    required_permissions = []

    def get_queryset(self):
        role = get_role(self.request.user)
        providers = get_providers(role)

        if not role.unlimited_visibility:
            self.allowed_providers = providers

        tenant_id = self.request.tenant_id

        # Return appropriate queryset per action
        if self.action == "findings_severity_timeseries":
            qs = DailySeveritySummary.objects.filter(tenant_id=tenant_id)
            if hasattr(self, "allowed_providers"):
                qs = qs.filter(provider_id__in=self.allowed_providers)
            return qs

        return ScanSummary.all_objects.filter(tenant_id=tenant_id)

    def get_serializer_class(self):
        if self.action == "providers":
            return OverviewProviderSerializer
        elif self.action == "providers_count":
            return OverviewProviderCountSerializer
        elif self.action == "findings":
            return OverviewFindingSerializer
        elif self.action == "findings_severity":
            return OverviewSeveritySerializer
        elif self.action == "findings_severity_timeseries":
            return FindingsSeverityOverTimeSerializer
        elif self.action == "services":
            return OverviewServiceSerializer
        elif self.action == "regions":
            return OverviewRegionSerializer
        elif self.action == "threatscore":
            return ThreatScoreSnapshotSerializer
        elif self.action == "attack_surface":
            return AttackSurfaceOverviewSerializer
        elif self.action == "categories":
            return CategoryOverviewSerializer
        elif self.action == "resource_groups":
            return ResourceGroupOverviewSerializer
        elif self.action == "compliance_watchlist":
            return ComplianceWatchlistOverviewSerializer
        return super().get_serializer_class()

    def get_filterset_class(self):
        if self.action == "providers":
            return None
        elif self.action in ["findings", "services", "regions"]:
            return ScanSummaryFilter
        elif self.action == "findings_severity":
            return ScanSummarySeverityFilter
        elif self.action == "findings_severity_timeseries":
            return DailySeveritySummaryFilter
        elif self.action == "categories":
            return CategoryOverviewFilter
        elif self.action == "resource_groups":
            return ResourceGroupOverviewFilter
        elif self.action == "attack_surface":
            return AttackSurfaceOverviewFilter
        elif self.action == "compliance_watchlist":
            return ComplianceWatchlistFilter
        return None

    def filter_queryset(self, queryset):
        # Skip OrderingFilter for findings_severity_timeseries (no inserted_at field)
        if self.action == "findings_severity_timeseries":
            return CustomDjangoFilterBackend().filter_queryset(
                self.request, queryset, self
            )
        return super().filter_queryset(queryset)

    @extend_schema(exclude=True)
    def list(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="GET")

    @extend_schema(exclude=True)
    def retrieve(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="GET")

    def _get_latest_scans_queryset(self):
        """
        Get filtered queryset for the latest completed scans per provider.

        Returns:
            Filtered ScanSummary queryset with latest scan IDs applied.
        """
        tenant_id = self.request.tenant_id
        queryset = self.get_queryset()
        filtered_queryset = self.filter_queryset(queryset)
        provider_filter = (
            {"provider__in": self.allowed_providers}
            if hasattr(self, "allowed_providers")
            else {}
        )

        latest_scan_ids = (
            Scan.all_objects.filter(
                tenant_id=tenant_id, state=StateChoices.COMPLETED, **provider_filter
            )
            .order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
            .values_list("id", flat=True)
        )

        return filtered_queryset.filter(
            tenant_id=tenant_id, scan_id__in=latest_scan_ids
        )

    def _normalize_jsonapi_params(self, query_params, exclude_keys=None):
        """Convert JSON:API filter params (filter[X]) to flat params (X)."""
        exclude_keys = exclude_keys or set()
        normalized = QueryDict(mutable=True)
        for key, values in query_params.lists():
            normalized_key = (
                key[7:-1] if key.startswith("filter[") and key.endswith("]") else key
            )
            if normalized_key not in exclude_keys:
                normalized.setlist(normalized_key, values)
        return normalized

    def _ensure_allowed_providers(self):
        """Populate allowed providers for RBAC-aware queries once per request."""
        if getattr(self, "_providers_initialized", False):
            return
        self.get_queryset()
        self._providers_initialized = True

    def _get_provider_filter(self, provider_field="provider"):
        self._ensure_allowed_providers()
        if hasattr(self, "allowed_providers"):
            return {f"{provider_field}__in": self.allowed_providers}
        return {}

    def _apply_provider_filter(self, queryset, provider_field="provider"):
        provider_filter = self._get_provider_filter(provider_field)
        if provider_filter:
            return queryset.filter(**provider_filter)
        return queryset

    def _apply_filterset(self, queryset, filterset_class, exclude_keys=None):
        normalized_params = self._normalize_jsonapi_params(
            self.request.query_params, exclude_keys=set(exclude_keys or [])
        )
        filterset = filterset_class(normalized_params, queryset=queryset)
        if not filterset.is_valid():
            raise ValidationError(filterset.errors)
        return filterset.qs

    def _latest_scan_ids_for_allowed_providers(self, tenant_id, provider_filters=None):
        provider_filter = self._get_provider_filter()
        queryset = Scan.all_objects.filter(
            tenant_id=tenant_id, state=StateChoices.COMPLETED, **provider_filter
        )
        if provider_filters:
            queryset = queryset.filter(**provider_filters)
        return (
            queryset.order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
            .values_list("id", flat=True)
        )

    def _extract_provider_filters_from_params(self):
        """Extract and validate provider filters from query params."""
        params = self.request.query_params
        filters = {}
        valid_provider_types = {c[0] for c in Provider.ProviderChoices.choices}

        provider_id = params.get("filter[provider_id]")
        if provider_id:
            filters["provider_id"] = provider_id

        provider_id_in = params.get("filter[provider_id__in]")
        if provider_id_in:
            filters["provider_id__in"] = provider_id_in.split(",")

        provider_type = params.get("filter[provider_type]")
        if provider_type:
            if provider_type not in valid_provider_types:
                raise ValidationError(
                    {"provider_type": f"Invalid choice: {provider_type}"}
                )
            filters["provider__provider"] = provider_type

        provider_type_in = params.get("filter[provider_type__in]")
        if provider_type_in:
            types = provider_type_in.split(",")
            invalid = [t for t in types if t not in valid_provider_types]
            if invalid:
                raise ValidationError(
                    {"provider_type__in": f"Invalid choices: {', '.join(invalid)}"}
                )
            filters["provider__provider__in"] = types

        return filters

    @action(detail=False, methods=["get"], url_name="providers")
    def providers(self, request):
        tenant_id = self.request.tenant_id
        queryset = self.get_queryset()
        provider_filter = (
            {"provider__in": self.allowed_providers}
            if hasattr(self, "allowed_providers")
            else {}
        )

        latest_scan_ids = (
            Scan.all_objects.filter(
                tenant_id=tenant_id, state=StateChoices.COMPLETED, **provider_filter
            )
            .order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
            .values_list("id", flat=True)
        )

        findings_aggregated = (
            queryset.filter(scan_id__in=latest_scan_ids)
            .values(provider=F("scan__provider__provider"))
            .annotate(
                findings_passed=Coalesce(Sum("_pass"), 0),
                findings_failed=Coalesce(Sum("fail"), 0),
                findings_muted=Coalesce(Sum("muted"), 0),
                total_findings=Coalesce(Sum("total"), 0),
            )
        )

        resources_queryset = Resource.all_objects.filter(tenant_id=tenant_id)
        if hasattr(self, "allowed_providers"):
            resources_queryset = resources_queryset.filter(
                provider__in=self.allowed_providers
            )
        resources_aggregated = resources_queryset.values(
            provider_type=F("provider__provider")
        ).annotate(total_resources=Count("id"))
        resource_map = {
            row["provider_type"]: row["total_resources"] for row in resources_aggregated
        }

        overview = []
        for row in findings_aggregated:
            overview.append(
                {
                    "provider": row["provider"],
                    "total_resources": resource_map.get(row["provider"], 0),
                    "total_findings": row["total_findings"],
                    "findings_passed": row["findings_passed"],
                    "findings_failed": row["findings_failed"],
                    "findings_muted": row["findings_muted"],
                }
            )

        return Response(
            self.get_serializer(overview, many=True).data,
            status=status.HTTP_200_OK,
        )

    @action(
        detail=False,
        methods=["get"],
        url_path="providers/count",
        url_name="providers-count",
    )
    def providers_count(self, request):
        tenant_id = self.request.tenant_id
        providers_qs = Provider.objects.filter(tenant_id=tenant_id)

        if hasattr(self, "allowed_providers"):
            allowed_ids = list(self.allowed_providers.values_list("id", flat=True))
            if not allowed_ids:
                overview = []
                return Response(
                    self.get_serializer(overview, many=True).data,
                    status=status.HTTP_200_OK,
                )
            providers_qs = providers_qs.filter(id__in=allowed_ids)

        overview = (
            providers_qs.values("provider")
            .annotate(count=Count("id"))
            .order_by("provider")
        )
        return Response(
            self.get_serializer(overview, many=True).data,
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["get"], url_name="findings")
    def findings(self, request):
        filtered_queryset = self._get_latest_scans_queryset()

        aggregated_totals = filtered_queryset.aggregate(
            _pass=Sum("_pass") or 0,
            fail=Sum("fail") or 0,
            muted=Sum("muted") or 0,
            total=Sum("total") or 0,
            new=Sum("new") or 0,
            changed=Sum("changed") or 0,
            unchanged=Sum("unchanged") or 0,
            fail_new=Sum("fail_new") or 0,
            fail_changed=Sum("fail_changed") or 0,
            pass_new=Sum("pass_new") or 0,
            pass_changed=Sum("pass_changed") or 0,
            muted_new=Sum("muted_new") or 0,
            muted_changed=Sum("muted_changed") or 0,
        )

        for key in aggregated_totals:
            if aggregated_totals[key] is None:
                aggregated_totals[key] = 0

        serializer = self.get_serializer(aggregated_totals)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_name="findings_severity")
    def findings_severity(self, request):
        filtered_queryset = self._get_latest_scans_queryset()

        # The filter will have added a status_count annotation if any status filter was used
        if "status_count" in filtered_queryset.query.annotations:
            sum_expression = Sum("status_count")
        else:
            # Exclude muted findings by default
            sum_expression = Sum(F("_pass") + F("fail"))

        severity_counts = (
            filtered_queryset.values("severity")
            .annotate(count=sum_expression)
            .order_by("severity")
        )

        severity_data = {sev[0]: 0 for sev in SeverityChoices}
        severity_data.update(
            {item["severity"]: item["count"] for item in severity_counts}
        )

        serializer = self.get_serializer(severity_data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_name="services")
    def services(self, request):
        filtered_queryset = self._get_latest_scans_queryset()

        services_data = (
            filtered_queryset.values("service")
            .annotate(_pass=Sum("_pass"))
            .annotate(fail=Sum("fail"))
            .annotate(muted=Sum("muted"))
            .annotate(total=Sum("total"))
            .order_by("service")
        )

        serializer = self.get_serializer(services_data, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_name="regions")
    def regions(self, request):
        filtered_queryset = self._get_latest_scans_queryset()

        regions_data = (
            filtered_queryset.annotate(provider_type=F("scan__provider__provider"))
            .values("provider_type", "region")
            .annotate(_pass=Sum("_pass"))
            .annotate(fail=Sum("fail"))
            .annotate(muted=Sum("muted"))
            .annotate(total=Sum("total"))
            .order_by("provider_type", "region")
        )

        serializer = self.get_serializer(regions_data, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["get"],
        url_path="findings_severity/timeseries",
        url_name="findings_severity_timeseries",
    )
    def findings_severity_timeseries(self, request):
        """
        Daily severity trends for charts. Uses DailySeveritySummary pre-aggregation.
        Requires date_from filter.
        """
        # Get queryset with RBAC, provider, and date filters applied
        # Date validation is handled by DailySeveritySummaryFilter
        daily_qs = self.filter_queryset(self.get_queryset())

        date_from = request._date_from
        date_to = request._date_to

        if not daily_qs.exists():
            # No data matches filters - return zeros
            result = self._generate_zero_result(date_from, date_to)
            serializer = self.get_serializer(result, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        # Fetch all data for fill-forward logic
        daily_summaries = list(
            daily_qs.order_by("provider_id", "-date").values(
                "provider_id",
                "scan_id",
                "date",
                "critical",
                "high",
                "medium",
                "low",
                "informational",
                "muted",
            )
        )

        if not daily_summaries:
            result = self._generate_zero_result(date_from, date_to)
            serializer = self.get_serializer(result, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        # Build provider_data: {provider_id: [(date, data), ...]} sorted by date desc
        provider_data = defaultdict(list)
        for summary in daily_summaries:
            provider_data[summary["provider_id"]].append(summary)

        # For each day, find the latest data per provider and sum values
        result = []
        current_date = date_from
        while current_date <= date_to:
            day_totals = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
                "muted": 0,
            }
            day_scan_ids = []

            for provider_id, summaries in provider_data.items():
                # Find the latest data for this provider <= current_date
                for summary in summaries:  # Already sorted by date desc
                    if summary["date"] <= current_date:
                        day_totals["critical"] += summary["critical"] or 0
                        day_totals["high"] += summary["high"] or 0
                        day_totals["medium"] += summary["medium"] or 0
                        day_totals["low"] += summary["low"] or 0
                        day_totals["informational"] += summary["informational"] or 0
                        day_totals["muted"] += summary["muted"] or 0
                        day_scan_ids.append(summary["scan_id"])
                        break  # Found the latest data for this provider

            result.append(
                {"date": current_date, "scan_ids": day_scan_ids, **day_totals}
            )
            current_date += timedelta(days=1)

        serializer = self.get_serializer(result, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def _generate_zero_result(self, date_from, date_to):
        """Generate a list of zero-filled results for each date in range."""
        result = []
        current_date = date_from
        zero_values = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "muted": 0,
            "scan_ids": [],
        }
        while current_date <= date_to:
            result.append({"date": current_date, **zero_values})
            current_date += timedelta(days=1)
        return result

    @extend_schema(
        summary="Get ThreatScore snapshots",
        description=(
            "Retrieve ThreatScore metrics. By default, returns the latest snapshot for each provider. "
            "Use snapshot_id to retrieve a specific historical snapshot."
        ),
        tags=["Overview"],
        parameters=[
            OpenApiParameter(
                name="snapshot_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.QUERY,
                description="Retrieve a specific snapshot by ID. If not provided, returns latest snapshots.",
            ),
            OpenApiParameter(
                name="provider_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.QUERY,
                description="Filter by specific provider ID",
            ),
            OpenApiParameter(
                name="provider_id__in",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Filter by multiple provider IDs (comma-separated UUIDs)",
            ),
            OpenApiParameter(
                name="provider_type",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Filter by provider type (aws, azure, gcp, etc.)",
            ),
            OpenApiParameter(
                name="provider_type__in",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Filter by multiple provider types (comma-separated)",
            ),
        ],
    )
    @action(detail=False, methods=["get"], url_name="threatscore")
    def threatscore(self, request):
        """
        Get ThreatScore snapshots.

        Default behavior: Returns the latest snapshot for each provider.
        With snapshot_id: Returns the specific snapshot requested.
        """
        tenant_id = self.request.tenant_id
        snapshot_id = request.query_params.get("snapshot_id")

        # Base queryset with RLS
        base_queryset = self._apply_provider_filter(
            ThreatScoreSnapshot.objects.filter(tenant_id=tenant_id)
        )

        # Case 1: Specific snapshot requested
        if snapshot_id:
            try:
                snapshot = base_queryset.get(id=snapshot_id)
                serializer = ThreatScoreSnapshotSerializer(
                    snapshot, context={"request": request}
                )
                return Response(serializer.data, status=status.HTTP_200_OK)
            except ThreatScoreSnapshot.DoesNotExist:
                raise NotFound(detail="ThreatScore snapshot not found")

        # Case 2: Latest snapshot per provider (default)
        # Apply filters manually: this @action is outside the standard list endpoint flow,
        # so DRF's filter backends don't execute and we must flatten JSON:API params ourselves.
        filtered_queryset = self._apply_filterset(
            base_queryset, ThreatScoreSnapshotFilter, exclude_keys={"snapshot_id"}
        )

        # Get distinct provider IDs from filtered queryset
        # Pick the latest snapshot per provider using Postgres DISTINCT ON pattern.
        # This avoids issuing one query per provider (N+1) when the filtered dataset is large.
        latest_snapshot_ids = list(
            filtered_queryset.order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
            .values_list("id", flat=True)
        )
        latest_snapshot_map = {
            snapshot.id: snapshot
            for snapshot in filtered_queryset.filter(id__in=latest_snapshot_ids)
        }
        latest_snapshots = [
            latest_snapshot_map[snapshot_id]
            for snapshot_id in latest_snapshot_ids
            if snapshot_id in latest_snapshot_map
        ]

        if len(latest_snapshots) <= 1:
            serializer = ThreatScoreSnapshotSerializer(
                latest_snapshots, many=True, context={"request": request}
            )
            return Response(serializer.data, status=status.HTTP_200_OK)

        snapshot_ids = [
            snapshot.id for snapshot in latest_snapshots if snapshot and snapshot.id
        ]
        aggregated_snapshot = self._build_threatscore_overview_snapshot(
            snapshot_ids, tenant_id
        )
        serializer = ThreatScoreSnapshotSerializer(
            [aggregated_snapshot], many=True, context={"request": request}
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    def _build_threatscore_overview_snapshot(self, snapshot_ids, tenant_id):
        """
        Aggregate the latest snapshots into a single overview snapshot for the tenant.
        """
        if not snapshot_ids:
            raise ValueError(
                "Snapshot id list cannot be empty when aggregating threatscore overview"
            )

        base_queryset = ThreatScoreSnapshot.objects.filter(
            tenant_id=tenant_id, id__in=snapshot_ids
        )

        annotated_queryset = (
            base_queryset.annotate(
                active_requirements=ExpressionWrapper(
                    F("total_requirements") - F("manual_requirements"),
                    output_field=IntegerField(),
                )
            )
            .annotate(
                weight=Case(
                    When(total_findings__gt=0, then=F("total_findings")),
                    When(
                        active_requirements__gt=0,
                        then=F("active_requirements"),
                    ),
                    default=Value(1, output_field=IntegerField()),
                    output_field=IntegerField(),
                )
            )
            .order_by()
        )

        aggregated_metrics = annotated_queryset.aggregate(
            total_requirements=Sum("total_requirements"),
            passed_requirements=Sum("passed_requirements"),
            failed_requirements=Sum("failed_requirements"),
            manual_requirements=Sum("manual_requirements"),
            total_findings=Sum("total_findings"),
            passed_findings=Sum("passed_findings"),
            failed_findings=Sum("failed_findings"),
            weighted_overall_sum=Sum(
                ExpressionWrapper(
                    F("overall_score") * F("weight"),
                    output_field=DecimalField(max_digits=14, decimal_places=4),
                )
            ),
            overall_weight=Sum("weight"),
            unweighted_overall_sum=Sum("overall_score"),
            weighted_delta_sum=Sum(
                Case(
                    When(
                        score_delta__isnull=False,
                        then=ExpressionWrapper(
                            F("score_delta") * F("weight"),
                            output_field=DecimalField(max_digits=14, decimal_places=4),
                        ),
                    ),
                    default=Value(
                        Decimal("0"),
                        output_field=DecimalField(max_digits=14, decimal_places=4),
                    ),
                    output_field=DecimalField(max_digits=14, decimal_places=4),
                )
            ),
            delta_weight=Sum(
                Case(
                    When(score_delta__isnull=False, then=F("weight")),
                    default=Value(0, output_field=IntegerField()),
                    output_field=IntegerField(),
                )
            ),
            provider_count=Count("id"),
            latest_inserted_at=Max("inserted_at"),
        )

        total_requirements = aggregated_metrics["total_requirements"] or 0
        passed_requirements = aggregated_metrics["passed_requirements"] or 0
        failed_requirements = aggregated_metrics["failed_requirements"] or 0
        manual_requirements = aggregated_metrics["manual_requirements"] or 0
        total_findings = aggregated_metrics["total_findings"] or 0
        passed_findings = aggregated_metrics["passed_findings"] or 0
        failed_findings = aggregated_metrics["failed_findings"] or 0

        weighted_overall_sum = aggregated_metrics["weighted_overall_sum"]
        if weighted_overall_sum is None:
            weighted_overall_sum = Decimal("0")
        unweighted_overall_sum = aggregated_metrics["unweighted_overall_sum"]
        if unweighted_overall_sum is None:
            unweighted_overall_sum = Decimal("0")

        overall_weight = aggregated_metrics["overall_weight"] or 0
        provider_count = aggregated_metrics["provider_count"] or 0

        weighted_delta_sum = aggregated_metrics["weighted_delta_sum"]
        if weighted_delta_sum is None:
            weighted_delta_sum = Decimal("0")
        delta_weight = aggregated_metrics["delta_weight"] or 0

        if overall_weight > 0:
            overall_score = (weighted_overall_sum / Decimal(overall_weight)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
        elif provider_count > 0:
            overall_score = (unweighted_overall_sum / Decimal(provider_count)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
        else:
            overall_score = Decimal("0.00")

        if delta_weight > 0:
            score_delta = (weighted_delta_sum / Decimal(delta_weight)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
        else:
            score_delta = None

        section_weighted_sums = defaultdict(lambda: Decimal("0"))
        section_weights = defaultdict(lambda: Decimal("0"))

        combined_critical_requirements = {}

        snapshots_with_weight = list(annotated_queryset)

        for snapshot in snapshots_with_weight:
            weight_value = getattr(snapshot, "weight", None)
            try:
                weight_decimal = Decimal(weight_value)
            except (InvalidOperation, TypeError):
                weight_decimal = Decimal("1")
            if weight_decimal <= 0:
                weight_decimal = Decimal("1")

            section_scores = snapshot.section_scores or {}
            for section, score in section_scores.items():
                try:
                    score_decimal = Decimal(str(score))
                except (InvalidOperation, TypeError):
                    continue
                section_weighted_sums[section] += score_decimal * weight_decimal
                section_weights[section] += weight_decimal

            for requirement in snapshot.critical_requirements or []:
                key = requirement.get("requirement_id") or requirement.get("title")
                if not key:
                    continue
                existing = combined_critical_requirements.get(key)

                def requirement_sort_key(item):
                    return (
                        item.get("risk_level") or 0,
                        item.get("weight") or 0,
                    )

                if existing is None or requirement_sort_key(
                    requirement
                ) > requirement_sort_key(existing):
                    combined_critical_requirements[key] = deepcopy(requirement)

        aggregated_section_scores = {}
        for section, total in section_weighted_sums.items():
            weight_total = section_weights[section]
            if weight_total > 0:
                aggregated_section_scores[section] = str(
                    (total / weight_total).quantize(
                        Decimal("0.01"), rounding=ROUND_HALF_UP
                    )
                )

        aggregated_section_scores = dict(sorted(aggregated_section_scores.items()))

        aggregated_critical_requirements = sorted(
            combined_critical_requirements.values(),
            key=lambda item: (
                item.get("risk_level") or 0,
                item.get("weight") or 0,
            ),
            reverse=True,
        )

        aggregated_snapshot = ThreatScoreSnapshot(
            tenant_id=tenant_id,
            scan=None,
            provider=None,
            compliance_id="prowler_threatscore_overview",
            overall_score=overall_score,
            score_delta=score_delta,
            section_scores=aggregated_section_scores,
            critical_requirements=aggregated_critical_requirements,
            total_requirements=total_requirements,
            passed_requirements=passed_requirements,
            failed_requirements=failed_requirements,
            manual_requirements=manual_requirements,
            total_findings=total_findings,
            passed_findings=passed_findings,
            failed_findings=failed_findings,
        )

        latest_inserted_at = aggregated_metrics["latest_inserted_at"]
        if latest_inserted_at is not None:
            aggregated_snapshot.inserted_at = latest_inserted_at

        aggregated_snapshot._aggregated = True

        return aggregated_snapshot

    @action(
        detail=False,
        methods=["get"],
        url_name="attack-surface",
        url_path="attack-surfaces",
    )
    def attack_surface(self, request):
        tenant_id = request.tenant_id
        latest_scan_ids = self._latest_scan_ids_for_allowed_providers(tenant_id)

        base_queryset = AttackSurfaceOverview.objects.filter(
            tenant_id=tenant_id, scan_id__in=latest_scan_ids
        )
        filtered_queryset = self._apply_filterset(
            base_queryset, AttackSurfaceOverviewFilter
        )

        aggregation = filtered_queryset.values("attack_surface_type").annotate(
            total_findings=Coalesce(Sum("total_findings"), 0),
            failed_findings=Coalesce(Sum("failed_findings"), 0),
            muted_failed_findings=Coalesce(Sum("muted_failed_findings"), 0),
        )

        results = {
            attack_surface_type: {
                "total_findings": 0,
                "failed_findings": 0,
                "muted_failed_findings": 0,
            }
            for attack_surface_type in AttackSurfaceOverview.AttackSurfaceTypeChoices.values
        }
        for item in aggregation:
            results[item["attack_surface_type"]] = {
                "total_findings": item["total_findings"],
                "failed_findings": item["failed_findings"],
                "muted_failed_findings": item["muted_failed_findings"],
            }

        response_data = [
            {"attack_surface_type": key, **value} for key, value in results.items()
        ]

        return Response(
            self.get_serializer(response_data, many=True).data,
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["get"], url_name="categories")
    def categories(self, request):
        tenant_id = request.tenant_id
        provider_filters = self._extract_provider_filters_from_params()
        latest_scan_ids = self._latest_scan_ids_for_allowed_providers(
            tenant_id, provider_filters
        )

        base_queryset = ScanCategorySummary.objects.filter(
            tenant_id=tenant_id, scan_id__in=latest_scan_ids
        )
        provider_filter_keys = {
            "provider_id",
            "provider_id__in",
            "provider_type",
            "provider_type__in",
        }
        filtered_queryset = self._apply_filterset(
            base_queryset, CategoryOverviewFilter, exclude_keys=provider_filter_keys
        )

        aggregation = (
            filtered_queryset.values("category", "severity")
            .annotate(
                total=Coalesce(Sum("total_findings"), 0),
                failed=Coalesce(Sum("failed_findings"), 0),
                new_failed=Coalesce(Sum("new_failed_findings"), 0),
            )
            .order_by("category", "severity")
        )

        category_data = defaultdict(
            lambda: {
                "total_findings": 0,
                "failed_findings": 0,
                "new_failed_findings": 0,
                "severity": {
                    "informational": 0,
                    "low": 0,
                    "medium": 0,
                    "high": 0,
                    "critical": 0,
                },
            }
        )

        for row in aggregation:
            cat = row["category"]
            sev = row["severity"]
            category_data[cat]["total_findings"] += row["total"]
            category_data[cat]["failed_findings"] += row["failed"]
            category_data[cat]["new_failed_findings"] += row["new_failed"]
            if sev in category_data[cat]["severity"]:
                category_data[cat]["severity"][sev] = row["failed"]

        response_data = [
            {"category": cat, **data} for cat, data in sorted(category_data.items())
        ]

        return Response(
            self.get_serializer(response_data, many=True).data,
            status=status.HTTP_200_OK,
        )

    @action(
        detail=False,
        methods=["get"],
        url_name="resource-groups",
        url_path="resource-groups",
    )
    def resource_groups(self, request):
        tenant_id = request.tenant_id
        provider_filters = self._extract_provider_filters_from_params()
        latest_scan_ids = self._latest_scan_ids_for_allowed_providers(
            tenant_id, provider_filters
        )

        base_queryset = ScanGroupSummary.objects.filter(
            tenant_id=tenant_id, scan_id__in=latest_scan_ids
        )
        provider_filter_keys = {
            "provider_id",
            "provider_id__in",
            "provider_type",
            "provider_type__in",
        }
        filtered_queryset = self._apply_filterset(
            base_queryset,
            ResourceGroupOverviewFilter,
            exclude_keys=provider_filter_keys,
        )

        aggregation = (
            filtered_queryset.values("resource_group", "severity")
            .annotate(
                total=Coalesce(Sum("total_findings"), 0),
                failed=Coalesce(Sum("failed_findings"), 0),
                new_failed=Coalesce(Sum("new_failed_findings"), 0),
            )
            .order_by("resource_group", "severity")
        )

        # Get resource_group-level resources_count:
        # 1. Max per (scan, resource_group) to deduplicate within-scan severity rows
        # 2. Sum across scans for cross-provider aggregation
        scan_resource_group_resources = filtered_queryset.values(
            "scan_id", "resource_group"
        ).annotate(resources=Coalesce(Max("resources_count"), 0))
        resources_by_resource_group = defaultdict(int)
        for row in scan_resource_group_resources:
            resources_by_resource_group[row["resource_group"]] += row["resources"]

        resource_group_data = defaultdict(
            lambda: {
                "total_findings": 0,
                "failed_findings": 0,
                "new_failed_findings": 0,
                "resources_count": 0,
                "severity": {
                    "informational": 0,
                    "low": 0,
                    "medium": 0,
                    "high": 0,
                    "critical": 0,
                },
            }
        )

        for row in aggregation:
            grp = row["resource_group"]
            sev = row["severity"]
            resource_group_data[grp]["total_findings"] += row["total"]
            resource_group_data[grp]["failed_findings"] += row["failed"]
            resource_group_data[grp]["new_failed_findings"] += row["new_failed"]
            if sev in resource_group_data[grp]["severity"]:
                resource_group_data[grp]["severity"][sev] = row["failed"]

        # Set resources_count from resource_group-level aggregation
        for grp in resource_group_data:
            resource_group_data[grp]["resources_count"] = (
                resources_by_resource_group.get(grp, 0)
            )

        response_data = [
            {"resource_group": grp, **data}
            for grp, data in sorted(resource_group_data.items())
        ]

        return Response(
            self.get_serializer(response_data, many=True).data,
            status=status.HTTP_200_OK,
        )

    @action(
        detail=False,
        methods=["get"],
        url_name="compliance-watchlist",
        url_path="compliance-watchlist",
    )
    def compliance_watchlist(self, request):
        """
        Get compliance watchlist overview with FAIL-dominant aggregation.

        Without filters: uses pre-aggregated TenantComplianceSummary (~70 rows).
        With provider filters: queries ProviderComplianceScore with FAIL-dominant logic.
        """
        tenant_id = request.tenant_id
        rbac_filter = self._get_provider_filter()
        query_params = request.query_params

        has_provider_filter = any(
            key.startswith("filter[provider") for key in query_params.keys()
        )
        has_rbac_restriction = bool(rbac_filter)

        if not has_provider_filter and not has_rbac_restriction:
            response_data = list(
                TenantComplianceSummary.objects.filter(tenant_id=tenant_id)
                .values(
                    "compliance_id",
                    "requirements_passed",
                    "requirements_failed",
                    "requirements_manual",
                    "total_requirements",
                )
                .order_by("compliance_id")
            )
        else:
            base_queryset = ProviderComplianceScore.objects.filter(
                tenant_id=tenant_id, **rbac_filter
            )

            filtered_queryset = self._apply_filterset(
                base_queryset, ComplianceWatchlistFilter
            )

            aggregation = (
                filtered_queryset.values("compliance_id", "requirement_id")
                .annotate(
                    has_fail=Sum(
                        Case(When(requirement_status="FAIL", then=1), default=0)
                    ),
                    has_manual=Sum(
                        Case(When(requirement_status="MANUAL", then=1), default=0)
                    ),
                )
                .values("compliance_id", "requirement_id", "has_fail", "has_manual")
            )

            compliance_data = defaultdict(
                lambda: {
                    "requirements_passed": 0,
                    "requirements_failed": 0,
                    "requirements_manual": 0,
                    "total_requirements": 0,
                }
            )

            for row in aggregation:
                cid = row["compliance_id"]
                compliance_data[cid]["total_requirements"] += 1

                if row["has_fail"] and row["has_fail"] > 0:
                    compliance_data[cid]["requirements_failed"] += 1
                elif row["has_manual"] and row["has_manual"] > 0:
                    compliance_data[cid]["requirements_manual"] += 1
                else:
                    compliance_data[cid]["requirements_passed"] += 1

            response_data = [
                {"compliance_id": cid, **data}
                for cid, data in sorted(compliance_data.items())
            ]

        return Response(
            self.get_serializer(response_data, many=True).data,
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["Schedule"])
@extend_schema_view(
    daily=extend_schema(
        summary="Create a daily schedule scan for a given provider",
        description="Schedules a daily scan for the specified provider. This endpoint creates a periodic task "
        "that will execute a scan every 24 hours.",
        request=ScheduleDailyCreateSerializer,
        responses={202: OpenApiResponse(response=TaskSerializer)},
    )
)
class ScheduleViewSet(BaseRLSViewSet):
    # TODO: change to Schedule when implemented
    queryset = Task.objects.none()
    http_method_names = ["post"]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        return super().get_queryset()

    def get_serializer_class(self):
        if self.action == "daily":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
            return ScheduleDailyCreateSerializer
        return super().get_serializer_class()

    @extend_schema(exclude=True)
    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="POST")

    @action(detail=False, methods=["post"], url_name="daily")
    def daily(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        provider_id = serializer.validated_data["provider_id"]

        provider_instance = get_object_or_404(Provider, pk=provider_id)
        with transaction.atomic():
            task = schedule_provider_scan(provider_instance)

        prowler_task = Task.objects.get(id=task.id)
        self.response_serializer_class = TaskSerializer
        output_serializer = self.get_serializer(prowler_task)

        return Response(
            data=output_serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": prowler_task.id}
                )
            },
        )


@extend_schema_view(
    list=extend_schema(
        tags=["Integration"],
        summary="List all integrations",
        description="Retrieve a list of all configured integrations with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        tags=["Integration"],
        summary="Retrieve integration details",
        description="Fetch detailed information about a specific integration by its ID.",
    ),
    create=extend_schema(
        tags=["Integration"],
        summary="Create a new integration",
        description="Register a new integration with the system, providing necessary configuration details.",
    ),
    partial_update=extend_schema(
        tags=["Integration"],
        summary="Partially update an integration",
        description="Modify certain fields of an existing integration without affecting other settings.",
    ),
    destroy=extend_schema(
        tags=["Integration"],
        summary="Delete an integration",
        description="Remove an integration from the system by its ID.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class IntegrationViewSet(BaseRLSViewSet):
    queryset = Integration.objects.all()
    serializer_class = IntegrationSerializer
    http_method_names = ["get", "post", "patch", "delete"]
    filterset_class = IntegrationFilter
    ordering = ["integration_type", "-inserted_at"]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_INTEGRATIONS]
    allowed_providers = None

    def get_queryset(self):
        user_roles = get_role(self.request.user)
        if user_roles.unlimited_visibility:
            # User has unlimited visibility, return all integrations
            queryset = Integration.objects.filter(tenant_id=self.request.tenant_id)
        else:
            # User lacks permission, filter providers based on provider groups associated with the role
            allowed_providers = get_providers(user_roles)
            queryset = Integration.objects.filter(providers__in=allowed_providers)
            self.allowed_providers = allowed_providers
        return queryset

    def get_serializer_class(self):
        if self.action == "create":
            return IntegrationCreateSerializer
        elif self.action == "partial_update":
            return IntegrationUpdateSerializer
        return super().get_serializer_class()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["allowed_providers"] = self.allowed_providers
        return context

    @extend_schema(
        tags=["Integration"],
        summary="Check integration connection",
        description="Try to verify integration connection",
        request=None,
        responses={202: OpenApiResponse(response=TaskSerializer)},
    )
    @action(detail=True, methods=["post"], url_name="connection")
    def connection(self, request, pk=None):
        get_object_or_404(Integration, pk=pk)
        with transaction.atomic():
            task = check_integration_connection_task.delay(
                integration_id=pk, tenant_id=self.request.tenant_id
            )
        prowler_task = Task.objects.get(id=task.id)
        serializer = TaskSerializer(prowler_task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": prowler_task.id}
                )
            },
        )


@extend_schema_view(
    dispatches=extend_schema(
        tags=["Integration"],
        summary="Send findings to a Jira integration",
        description="Send a set of filtered findings to the given integration. At least one finding filter must be "
        "provided.",
        responses={202: OpenApiResponse(response=TaskSerializer)},
        filters=True,
    )
)
class IntegrationJiraViewSet(BaseRLSViewSet):
    queryset = Finding.all_objects.all()
    serializer_class = IntegrationJiraDispatchSerializer
    http_method_names = ["post"]
    filter_backends = [CustomDjangoFilterBackend]
    filterset_class = IntegrationJiraFindingsFilter
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_INTEGRATIONS]

    @extend_schema(exclude=True)
    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="POST")

    def get_queryset(self):
        tenant_id = self.request.tenant_id
        user_roles = get_role(self.request.user)
        if user_roles.unlimited_visibility:
            # User has unlimited visibility, return all findings
            queryset = Finding.all_objects.filter(tenant_id=tenant_id)
        else:
            # User lacks permission, filter findings based on provider groups associated with the role
            queryset = Finding.all_objects.filter(
                scan__provider__in=get_providers(user_roles)
            )

        return queryset

    @action(detail=False, methods=["post"], url_name="dispatches")
    def dispatches(self, request, integration_pk=None):
        get_object_or_404(Integration, pk=integration_pk)
        serializer = self.get_serializer(
            data=request.data, context={"integration_id": integration_pk}
        )
        serializer.is_valid(raise_exception=True)

        if self.filter_queryset(self.get_queryset()).count() == 0:
            raise ValidationError(
                {"findings": "No findings match the provided filters"}
            )

        finding_ids = [
            str(finding_id)
            for finding_id in self.filter_queryset(self.get_queryset()).values_list(
                "id", flat=True
            )
        ]
        project_key = serializer.validated_data["project_key"]
        issue_type = serializer.validated_data["issue_type"]

        with transaction.atomic():
            task = jira_integration_task.delay(
                tenant_id=self.request.tenant_id,
                integration_id=integration_pk,
                project_key=project_key,
                issue_type=issue_type,
                finding_ids=finding_ids,
            )
        prowler_task = Task.objects.get(id=task.id)
        serializer = TaskSerializer(prowler_task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": prowler_task.id}
                )
            },
        )


@extend_schema_view(
    list=extend_schema(
        tags=["Lighthouse AI"],
        summary="List all Lighthouse AI configurations",
        description="Retrieve a list of all Lighthouse AI configurations.",
        deprecated=True,
    ),
    create=extend_schema(
        tags=["Lighthouse AI"],
        summary="Create a new Lighthouse AI configuration",
        description="Create a new Lighthouse AI configuration with the specified details.",
        deprecated=True,
    ),
    partial_update=extend_schema(
        tags=["Lighthouse AI"],
        summary="Partially update a Lighthouse AI configuration",
        description="Update certain fields of an existing Lighthouse AI configuration.",
        deprecated=True,
    ),
    destroy=extend_schema(
        tags=["Lighthouse AI"],
        summary="Delete a Lighthouse AI configuration",
        description="Remove a Lighthouse AI configuration by its ID.",
        deprecated=True,
    ),
    connection=extend_schema(
        tags=["Lighthouse AI"],
        summary="Check the connection to the OpenAI API",
        description="Verify the connection to the OpenAI API for a specific Lighthouse AI configuration.",
        request=None,
        responses={202: OpenApiResponse(response=TaskSerializer)},
        deprecated=True,
    ),
)
class LighthouseConfigViewSet(BaseRLSViewSet):
    """
    API endpoint for managing Lighthouse configuration.
    """

    serializer_class = LighthouseConfigSerializer
    ordering_fields = ["name", "inserted_at", "updated_at", "is_active"]
    ordering = ["-inserted_at"]

    def get_queryset(self):
        return LighthouseConfiguration.objects.filter(tenant_id=self.request.tenant_id)

    def get_serializer_class(self):
        if self.action == "create":
            return LighthouseConfigCreateSerializer
        elif self.action == "partial_update":
            return LighthouseConfigUpdateSerializer
        elif self.action == "connection":
            return TaskSerializer
        return super().get_serializer_class()

    @extend_schema(exclude=True)
    def retrieve(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="GET")

    @action(detail=True, methods=["post"], url_name="connection")
    def connection(self, request, pk=None):
        """
        Check the connection to the OpenAI API asynchronously.
        """
        instance = self.get_object()
        with transaction.atomic():
            task = check_lighthouse_connection_task.delay(
                lighthouse_config_id=str(instance.id), tenant_id=self.request.tenant_id
            )
        prowler_task = Task.objects.get(id=task.id)
        serializer = TaskSerializer(prowler_task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": prowler_task.id}
                )
            },
        )


@extend_schema_view(
    list=extend_schema(
        tags=["Lighthouse AI"],
        summary="List all LLM provider configurations",
        description="Retrieve all LLM provider configurations for the current tenant",
    ),
    retrieve=extend_schema(
        tags=["Lighthouse AI"],
        summary="Retrieve LLM provider configuration",
        description="Get details for a specific provider configuration in the current tenant.",
    ),
    create=extend_schema(
        tags=["Lighthouse AI"],
        summary="Create LLM provider configuration",
        description="Create a per-tenant configuration for an LLM provider. Only one configuration per provider type "
        "is allowed per tenant.",
    ),
    partial_update=extend_schema(
        tags=["Lighthouse AI"],
        summary="Update LLM provider configuration",
        description="Partially update a provider configuration (e.g., base_url, is_active).",
    ),
    destroy=extend_schema(
        tags=["Lighthouse AI"],
        summary="Delete LLM provider configuration",
        description="Delete a provider configuration. Any tenant defaults that reference this provider are cleared "
        "during deletion.",
    ),
)
class LighthouseProviderConfigViewSet(BaseRLSViewSet):
    queryset = LighthouseProviderConfiguration.objects.all()
    serializer_class = LighthouseProviderConfigSerializer
    http_method_names = ["get", "post", "patch", "delete"]
    filterset_class = LighthouseProviderConfigFilter

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return LighthouseProviderConfiguration.objects.none()
        return LighthouseProviderConfiguration.objects.filter(
            tenant_id=self.request.tenant_id
        )

    def get_serializer_class(self):
        if self.action == "create":
            return LighthouseProviderConfigCreateSerializer
        elif self.action == "partial_update":
            return LighthouseProviderConfigUpdateSerializer
        elif self.action in ["connection", "refresh_models"]:
            return TaskSerializer
        return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        read_serializer = LighthouseProviderConfigSerializer(
            instance, context=self.get_serializer_context()
        )
        headers = self.get_success_headers(read_serializer.data)
        return Response(
            data=read_serializer.data,
            status=status.HTTP_201_CREATED,
            headers=headers,
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(
            instance,
            data=request.data,
            partial=True,
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        read_serializer = LighthouseProviderConfigSerializer(
            instance, context=self.get_serializer_context()
        )
        return Response(data=read_serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        tags=["Lighthouse AI"],
        summary="Check LLM provider connection",
        description="Validate provider credentials asynchronously and toggle is_active.",
        request=None,
        responses={202: OpenApiResponse(response=TaskSerializer)},
    )
    @action(detail=True, methods=["post"], url_name="connection")
    def connection(self, request, pk=None):
        instance = self.get_object()

        with transaction.atomic():
            task = check_lighthouse_provider_connection_task.delay(
                provider_config_id=str(instance.id), tenant_id=self.request.tenant_id
            )

        prowler_task = Task.objects.get(id=task.id)
        serializer = TaskSerializer(prowler_task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": prowler_task.id}
                )
            },
        )

    @extend_schema(
        tags=["Lighthouse AI"],
        summary="Refresh LLM models catalog",
        description="Fetch available models for this provider configuration and upsert into catalog. Supports OpenAI, OpenAI-compatible, and AWS Bedrock providers.",
        request=None,
        responses={202: OpenApiResponse(response=TaskSerializer)},
    )
    @action(
        detail=True,
        methods=["post"],
        url_path="refresh-models",
        url_name="refresh-models",
    )
    def refresh_models(self, request, pk=None):
        instance = self.get_object()

        with transaction.atomic():
            task = refresh_lighthouse_provider_models_task.delay(
                provider_config_id=str(instance.id), tenant_id=self.request.tenant_id
            )

        prowler_task = Task.objects.get(id=task.id)
        serializer = TaskSerializer(prowler_task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": prowler_task.id}
                )
            },
        )


@extend_schema_view(
    list=extend_schema(
        tags=["Lighthouse AI"],
        summary="Get Lighthouse AI Tenant config",
        description="Retrieve current tenant-level Lighthouse AI settings. Returns a single configuration object.",
    ),
    partial_update=extend_schema(
        tags=["Lighthouse AI"],
        summary="Update Lighthouse AI Tenant config",
        description="Update tenant-level settings. Validates that the default provider is configured and active and that default model IDs exist for the chosen providers. Auto-creates configuration if it doesn't exist.",
    ),
)
class LighthouseTenantConfigViewSet(BaseRLSViewSet):
    """
    Singleton endpoint for tenant-level Lighthouse AI configuration.

    This viewset implements a true singleton pattern:
    - GET returns the single configuration object (or 404 if not found)
    - PATCH updates/creates the configuration (upsert semantics)
    - No ID is required in the URL
    """

    queryset = LighthouseTenantConfiguration.objects.all()
    serializer_class = LighthouseTenantConfigSerializer
    http_method_names = ["get", "patch"]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return LighthouseTenantConfiguration.objects.none()
        return LighthouseTenantConfiguration.objects.filter(
            tenant_id=self.request.tenant_id
        )

    def get_serializer_class(self):
        if self.action == "partial_update":
            return LighthouseTenantConfigUpdateSerializer
        return super().get_serializer_class()

    def get_object(self):
        """Retrieve the singleton instance for the current tenant."""
        obj = LighthouseTenantConfiguration.objects.filter(
            tenant_id=self.request.tenant_id
        ).first()
        if obj is None:
            raise NotFound("Tenant Lighthouse configuration not found")
        self.check_object_permissions(self.request, obj)
        return obj

    def list(self, request, *args, **kwargs):
        """GET endpoint for singleton - returns single object, not an array."""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        """PATCH endpoint for singleton - no pk required. Auto-creates if not exists."""
        # Auto-create tenant config if it doesn't exist (upsert semantics)
        instance, created = LighthouseTenantConfiguration.objects.get_or_create(
            tenant_id=self.request.tenant_id,
            defaults={},
        )

        # Extract attributes from JSON:API payload
        try:
            payload = json.loads(request.body)
            attributes = payload.get("data", {}).get("attributes", {})
        except (json.JSONDecodeError, AttributeError):
            raise ValidationError("Invalid JSON:API payload")

        serializer = self.get_serializer(instance, data=attributes, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        read_serializer = LighthouseTenantConfigSerializer(
            instance, context=self.get_serializer_context()
        )
        return Response(read_serializer.data, status=status.HTTP_200_OK)


@extend_schema_view(
    list=extend_schema(
        tags=["Lighthouse AI"],
        summary="List all LLM models",
        description="List available LLM models per configured provider for the current tenant.",
    ),
    retrieve=extend_schema(
        tags=["Lighthouse AI"],
        summary="Retrieve LLM model details",
        description="Get details for a specific LLM model.",
    ),
)
class LighthouseProviderModelsViewSet(BaseRLSViewSet):
    queryset = LighthouseProviderModels.objects.all()
    serializer_class = LighthouseProviderModelsSerializer
    filterset_class = LighthouseProviderModelsFilter
    # Expose as read-only catalog collection
    http_method_names = ["get"]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return LighthouseProviderModels.objects.none()
        return LighthouseProviderModels.objects.filter(tenant_id=self.request.tenant_id)

    def get_serializer_class(self):
        return super().get_serializer_class()


@extend_schema_view(
    list=extend_schema(
        tags=["Processor"],
        summary="List all processors",
        description="Retrieve a list of all configured processors with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        tags=["Processor"],
        summary="Retrieve processor details",
        description="Fetch detailed information about a specific processor by its ID.",
    ),
    create=extend_schema(
        tags=["Processor"],
        summary="Create a new processor",
        description="Register a new processor with the system, providing necessary configuration details. There can "
        "only be one processor of each type per tenant.",
    ),
    partial_update=extend_schema(
        tags=["Processor"],
        summary="Partially update a processor",
        description="Modify certain fields of an existing processor without affecting other settings.",
    ),
    destroy=extend_schema(
        tags=["Processor"],
        summary="Delete a processor",
        description="Remove a processor from the system by its ID.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ProcessorViewSet(BaseRLSViewSet):
    queryset = Processor.objects.all()
    serializer_class = ProcessorSerializer
    http_method_names = ["get", "post", "patch", "delete"]
    filterset_class = ProcessorFilter
    ordering = ["processor_type", "-inserted_at"]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_ACCOUNT]

    def get_queryset(self):
        queryset = Processor.objects.filter(tenant_id=self.request.tenant_id)
        return queryset

    def get_serializer_class(self):
        if self.action == "create":
            return ProcessorCreateSerializer
        elif self.action == "partial_update":
            return ProcessorUpdateSerializer
        return super().get_serializer_class()


@extend_schema_view(
    list=extend_schema(
        tags=["API Keys"],
        summary="List API keys",
        description="Retrieve a list of API keys for the tenant, with filtering support.",
    ),
    retrieve=extend_schema(
        tags=["API Keys"],
        summary="Retrieve API key details",
        description="Fetch detailed information about a specific API key by its ID.",
    ),
    create=extend_schema(
        tags=["API Keys"],
        summary="Create a new API key",
        description="Create a new API key for the tenant.",
    ),
    partial_update=extend_schema(
        tags=["API Keys"],
        summary="Partially update an API key",
        description="Modify certain fields of an existing API key without affecting other settings.",
    ),
    revoke=extend_schema(
        tags=["API Keys"],
        summary="Revoke an API key",
        description="Revoke an API key by its ID. This action is irreversible and will prevent the key from being "
        "used.",
        request=None,
        responses={
            200: OpenApiResponse(
                response=TenantApiKeySerializer,
                description="API key was successfully revoked",
            )
        },
    ),
)
class TenantApiKeyViewSet(BaseRLSViewSet):
    queryset = TenantAPIKey.objects.all()
    serializer_class = TenantApiKeySerializer
    filterset_class = TenantApiKeyFilter
    http_method_names = ["get", "post", "patch", "delete"]
    ordering = ["revoked", "-created"]
    ordering_fields = ["name", "prefix", "revoked", "inserted_at", "expires_at"]
    # RBAC required permissions
    required_permissions = [Permissions.MANAGE_ACCOUNT]

    def get_queryset(self):
        queryset = TenantAPIKey.objects.filter(
            tenant_id=self.request.tenant_id
        ).annotate(inserted_at=F("created"), expires_at=F("expiry_date"))
        return queryset

    def get_serializer_class(self):
        if self.action == "create":
            return TenantApiKeyCreateSerializer
        elif self.action == "partial_update":
            return TenantApiKeyUpdateSerializer
        return super().get_serializer_class()

    @extend_schema(exclude=True)
    def destroy(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="DELETE")

    @action(detail=True, methods=["delete"])
    def revoke(self, request, *args, **kwargs):
        instance = self.get_object()

        # Check if already revoked
        if instance.revoked:
            raise ValidationError(
                {
                    "detail": "API key is already revoked",
                }
            )

        TenantAPIKey.objects.revoke_api_key(instance.pk)
        instance.refresh_from_db()

        serializer = self.get_serializer(instance)
        return Response(data=serializer.data, status=status.HTTP_200_OK)


# MuteRules
@extend_schema_view(
    list=extend_schema(
        tags=["Mute Rules"],
        summary="List all mute rules",
        description="Retrieve a list of all mute rules with filtering options.",
    ),
    retrieve=extend_schema(
        tags=["Mute Rules"],
        summary="Retrieve a mute rule",
        description="Fetch detailed information about a specific mute rule by ID.",
    ),
    create=extend_schema(
        tags=["Mute Rules"],
        summary="Create a new mute rule",
        description="Create a new mute rule by providing finding IDs, name, and reason. "
        "The rule will immediately mute the selected findings and launch a background task "
        "to mute all historical findings with matching UIDs.",
        request=MuteRuleCreateSerializer,
    ),
    partial_update=extend_schema(
        tags=["Mute Rules"],
        summary="Partially update a mute rule",
        description="Update certain fields of an existing mute rule (e.g., name, reason, enabled).",
        request=MuteRuleUpdateSerializer,
        responses={200: MuteRuleSerializer},
    ),
    destroy=extend_schema(
        tags=["Mute Rules"],
        summary="Delete a mute rule",
        description="Remove a mute rule from the system. Note: Previously muted findings remain muted.",
    ),
)
class MuteRuleViewSet(BaseRLSViewSet):
    queryset = MuteRule.objects.all()
    serializer_class = MuteRuleSerializer
    filterset_class = MuteRuleFilter
    http_method_names = ["get", "post", "patch", "delete"]
    search_fields = ["name", "reason"]
    ordering = ["-inserted_at"]
    ordering_fields = [
        "name",
        "enabled",
        "inserted_at",
        "updated_at",
    ]
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        queryset = MuteRule.objects.filter(tenant_id=self.request.tenant_id)
        return queryset.select_related("created_by")

    def get_serializer_class(self):
        if self.action == "create":
            return MuteRuleCreateSerializer
        elif self.action == "partial_update":
            return MuteRuleUpdateSerializer
        return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create the mute rule
        mute_rule = serializer.save()

        tenant_id = str(request.tenant_id)
        finding_ids = request.data.get("finding_ids", [])

        # Immediately mute the selected findings
        Finding.all_objects.filter(
            id__in=finding_ids, tenant_id=tenant_id, muted=False
        ).update(
            muted=True,
            muted_at=mute_rule.inserted_at,
            muted_reason=mute_rule.reason,
        )

        # Launch background task for historical muting
        with transaction.atomic():
            mute_historical_findings_task.apply_async(
                kwargs={"tenant_id": tenant_id, "mute_rule_id": str(mute_rule.id)}
            )

        # Return the created mute rule
        serializer = self.get_serializer(mute_rule)
        return Response(
            data=serializer.data,
            status=status.HTTP_201_CREATED,
        )
