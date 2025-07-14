import glob
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

import sentry_sdk
from allauth.socialaccount.models import SocialAccount, SocialApp
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.saml.views import FinishACSView, LoginView
from botocore.exceptions import ClientError, NoCredentialsError, ParamValidationError
from celery.result import AsyncResult
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
from django.db.models import Count, Exists, F, OuterRef, Prefetch, Q, Sum
from django.db.models.functions import Coalesce
from django.http import HttpResponse
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
from tasks.jobs.export import get_s3_client
from tasks.tasks import (
    backfill_scan_resource_summaries_task,
    check_lighthouse_connection_task,
    check_provider_connection_task,
    delete_provider_task,
    delete_tenant_task,
    perform_scan_task,
)

from api.base_views import BaseRLSViewSet, BaseTenantViewset, BaseUserViewset
from api.compliance import (
    PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE,
    get_compliance_frameworks,
)
from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.exceptions import TaskFailedException
from api.filters import (
    ComplianceOverviewFilter,
    FindingFilter,
    IntegrationFilter,
    InvitationFilter,
    LatestFindingFilter,
    MembershipFilter,
    ProcessorFilter,
    ProviderFilter,
    ProviderGroupFilter,
    ProviderSecretFilter,
    ResourceFilter,
    RoleFilter,
    ScanFilter,
    ScanSummaryFilter,
    ServiceOverviewFilter,
    TaskFilter,
    TenantFilter,
    UserFilter,
)
from api.models import (
    ComplianceOverview,
    ComplianceRequirementOverview,
    Finding,
    Integration,
    Invitation,
    LighthouseConfiguration,
    Membership,
    Processor,
    Provider,
    ProviderGroup,
    ProviderGroupMembership,
    ProviderSecret,
    Resource,
    ResourceFindingMapping,
    ResourceScanSummary,
    Role,
    RoleProviderGroupRelationship,
    SAMLConfiguration,
    SAMLDomainIndex,
    SAMLToken,
    Scan,
    ScanSummary,
    SeverityChoices,
    StateChoices,
    Task,
    User,
    UserRoleRelationship,
)
from api.pagination import ComplianceOverviewPagination
from api.rbac.permissions import Permissions, get_providers, get_role
from api.rls import Tenant
from api.utils import (
    CustomOAuth2Client,
    get_findings_metadata_no_aggregations,
    validate_invitation,
)
from api.uuid_utils import datetime_to_uuid7, uuid7_start
from api.v1.mixins import PaginateByPkMixin, TaskManagementMixin
from api.v1.serializers import (
    ComplianceOverviewAttributesSerializer,
    ComplianceOverviewDetailSerializer,
    ComplianceOverviewMetadataSerializer,
    ComplianceOverviewSerializer,
    FindingDynamicFilterSerializer,
    FindingMetadataSerializer,
    FindingSerializer,
    IntegrationCreateSerializer,
    IntegrationSerializer,
    IntegrationUpdateSerializer,
    InvitationAcceptSerializer,
    InvitationCreateSerializer,
    InvitationSerializer,
    InvitationUpdateSerializer,
    LighthouseConfigCreateSerializer,
    LighthouseConfigSerializer,
    LighthouseConfigUpdateSerializer,
    MembershipSerializer,
    OverviewFindingSerializer,
    OverviewProviderSerializer,
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
    TenantSerializer,
    TokenRefreshSerializer,
    TokenSerializer,
    TokenSocialLoginSerializer,
    TokenSwitchTenantSerializer,
    UserCreateSerializer,
    UserRoleRelationshipSerializer,
    UserSerializer,
    UserUpdateSerializer,
)

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
        spectacular_settings.VERSION = "1.9.0"
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
                "name": "Provider",
                "description": "Endpoints for managing providers (AWS, GCP, Azure, etc...).",
            },
            {
                "name": "Provider Group",
                "description": "Endpoints for managing provider groups.",
            },
            {
                "name": "Scan",
                "description": "Endpoints for triggering manual scans and viewing scan results.",
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
                "name": "Overview",
                "description": "Endpoints for retrieving aggregated summaries of resources from the system.",
            },
            {
                "name": "Compliance Overview",
                "description": "Endpoints for checking the compliance overview, allowing filtering by scan, provider or"
                " compliance framework ID.",
            },
            {
                "name": "Task",
                "description": "Endpoints for task management, allowing retrieval of task status and "
                "revoking tasks that have not started.",
            },
            {
                "name": "Integration",
                "description": "Endpoints for managing third-party integrations, including registration, configuration,"
                " retrieval, and deletion of integrations such as S3, JIRA, or other services.",
            },
            {
                "name": "Lighthouse",
                "description": "Endpoints for managing Lighthouse configurations, including creation, retrieval, "
                "updating, and deletion of configurations such as OpenAI keys, models, and business context.",
            },
            {
                "name": "Processor",
                "description": "Endpoints for managing post-processors used to process Prowler findings, including "
                "registration, configuration, and deletion of post-processing actions.",
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
    def dispatch(self, request, organization_slug):
        super().dispatch(request, organization_slug)
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
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
        ):
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
        try:
            role = Role.objects.using(MainRouter.admin_db).get(
                name=role_name, tenant=tenant
            )
        except Role.DoesNotExist:
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

        return super().destroy(request, *args, **kwargs)

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
        description="Update the user-roles relationship information without affecting other fields.",
        responses={
            204: OpenApiResponse(
                response=None, description="Relationship updated successfully"
            )
        },
    ),
    destroy=extend_schema(
        tags=["User"],
        summary="Delete a user-roles relationship",
        description="Remove the user-roles relationship from the system by their ID.",
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
    required_permissions = [Permissions.MANAGE_USERS]

    def get_queryset(self):
        return User.objects.filter(membership__tenant__id=self.request.tenant_id)

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

    def destroy(self, request, *args, **kwargs):
        user = self.get_object()
        user.roles.clear()

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
class ProviderViewSet(BaseRLSViewSet):
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
                keys = [obj["Key"] for obj in contents if obj["Key"].endswith(suffix)]
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
                    # checks_to_execute=scan.scanner_args.get("checks_to_execute"),
                },
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
        tags=["Resource"],
        summary="List all resources",
        description="Retrieve a list of all resources with options for filtering by various criteria. Resources are "
        "objects that are discovered by Prowler. They can be anything from a single host to a whole VPC.",
    ),
    retrieve=extend_schema(
        tags=["Resource"],
        summary="Retrieve data for a resource",
        description="Fetch detailed information about a specific resource by their ID. A Resource is an object that "
        "is discovered by Prowler. It can be anything from a single host to a whole VPC.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ResourceViewSet(BaseRLSViewSet):
    queryset = Resource.objects.all()
    serializer_class = ResourceSerializer
    http_method_names = ["get"]
    filterset_class = ResourceFilter
    ordering = ["-inserted_at"]
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
    # RBAC required permissions (implicit -> MANAGE_PROVIDERS enable unlimited visibility or check the visibility of
    # the provider through the provider group)
    required_permissions = []

    def get_queryset(self):
        user_roles = get_role(self.request.user)
        if user_roles.unlimited_visibility:
            # User has unlimited visibility, return all scans
            queryset = Resource.objects.filter(tenant_id=self.request.tenant_id)
        else:
            # User lacks permission, filter providers based on provider groups associated with the role
            queryset = Resource.objects.filter(
                tenant_id=self.request.tenant_id, provider__in=get_providers(user_roles)
            )

        search_value = self.request.query_params.get("filter[search]", None)
        if search_value:
            # Django's ORM will build a LEFT JOIN and OUTER JOIN on the "through" table, resulting in duplicates
            # The duplicates then require a `distinct` query
            search_query = SearchQuery(
                search_value, config="simple", search_type="plain"
            )
            queryset = queryset.filter(
                Q(tags__key=search_value)
                | Q(tags__value=search_value)
                | Q(tags__text_search=search_query)
                | Q(tags__key__contains=search_value)
                | Q(tags__value__contains=search_value)
                | Q(uid=search_value)
                | Q(name=search_value)
                | Q(region=search_value)
                | Q(service=search_value)
                | Q(type=search_value)
                | Q(text_search=search_query)
                | Q(uid__contains=search_value)
                | Q(name__contains=search_value)
                | Q(region__contains=search_value)
                | Q(service__contains=search_value)
                | Q(type__contains=search_value)
            ).distinct()

        return queryset


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

            resource_match = Resource.all_objects.filter(
                text_search=search_query,
                id__in=ResourceFindingMapping.objects.filter(
                    resource_id=OuterRef("pk"),
                    tenant_id=tenant_id,
                ).values("resource_id"),
            )

            queryset = queryset.filter(
                Q(text_search=search_query) | Q(Exists(resource_match))
            )

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

        if scans := query_params.get("filter[scan__in]") or query_params.get(
            "filter[scan]"
        ):
            queryset = queryset.filter(scan_id__in=scans.split(","))
            scan_based_filters = {"id__in": scans.split(",")}
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

        result = {
            "services": services,
            "regions": regions,
            "resource_types": resource_types,
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

        result = {
            "services": services,
            "regions": regions,
            "resource_types": resource_types,
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
        description="Update certain fields of an existing role's information without affecting other fields.",
        responses={200: RoleSerializer},
    ),
    destroy=extend_schema(
        tags=["Role"],
        summary="Delete a role",
        description="Remove a role from the system by their ID.",
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

    def partial_update(self, request, *args, **kwargs):
        user_role = get_role(request.user)
        # If the user is the owner of the role, the manage_account field is not editable
        if user_role and kwargs["pk"] == str(user_role.id):
            request.data["manage_account"] = str(user_role.manage_account).lower()
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if (
            instance.name == "admin"
        ):  # TODO: Move to a constant/enum (in case other roles are created by default)
            raise ValidationError(detail="The admin role cannot be deleted.")

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
            202: OpenApiResponse(description="The task is in progress"),
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
            202: OpenApiResponse(description="The task is in progress"),
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

    def list(self, request, *args, **kwargs):
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
        try:
            if task := self.get_task_response_if_running(
                task_name="scan-compliance-overviews",
                task_kwargs={"tenant_id": self.request.tenant_id, "scan_id": scan_id},
                raise_on_not_found=False,
            ):
                return task
        except TaskFailedException:
            return Response(
                {"detail": "Task failed to generate compliance overview data."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        queryset = self.filter_queryset(self.filter_queryset(self.get_queryset()))

        requirement_status_subquery = queryset.values(
            "compliance_id", "requirement_id"
        ).annotate(
            fail_count=Count("id", filter=Q(requirement_status="FAIL")),
            pass_count=Count("id", filter=Q(requirement_status="PASS")),
            total_count=Count("id"),
        )

        compliance_data = {}
        framework_info = {}

        for item in queryset.values("compliance_id", "framework", "version").distinct():
            framework_info[item["compliance_id"]] = {
                "framework": item["framework"],
                "version": item["version"],
            }

        for item in requirement_status_subquery:
            compliance_id = item["compliance_id"]

            if item["fail_count"] > 0:
                req_status = "FAIL"
            elif item["pass_count"] == item["total_count"]:
                req_status = "PASS"
            else:
                req_status = "MANUAL"

            if compliance_id not in compliance_data:
                compliance_data[compliance_id] = {
                    "total_requirements": 0,
                    "requirements_passed": 0,
                    "requirements_failed": 0,
                    "requirements_manual": 0,
                }

            compliance_data[compliance_id]["total_requirements"] += 1
            if req_status == "PASS":
                compliance_data[compliance_id]["requirements_passed"] += 1
            elif req_status == "FAIL":
                compliance_data[compliance_id]["requirements_failed"] += 1
            else:
                compliance_data[compliance_id]["requirements_manual"] += 1

        response_data = []
        for compliance_id, data in compliance_data.items():
            framework = framework_info.get(compliance_id, {})

            response_data.append(
                {
                    "id": compliance_id,
                    "compliance_id": compliance_id,
                    "framework": framework.get("framework", ""),
                    "version": framework.get("version", ""),
                    "requirements_passed": data["requirements_passed"],
                    "requirements_failed": data["requirements_failed"],
                    "requirements_manual": data["requirements_manual"],
                    "total_requirements": data["total_requirements"],
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
        try:
            if task := self.get_task_response_if_running(
                task_name="scan-compliance-overviews",
                task_kwargs={"tenant_id": self.request.tenant_id, "scan_id": scan_id},
                raise_on_not_found=False,
            ):
                return task
        except TaskFailedException:
            return Response(
                {"detail": "Task failed to generate compliance overview data."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        regions = list(
            self.get_queryset()
            .filter(scan_id=scan_id)
            .values_list("region", flat=True)
            .order_by("region")
            .distinct()
        )
        result = {"regions": regions}

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
        try:
            if task := self.get_task_response_if_running(
                task_name="scan-compliance-overviews",
                task_kwargs={"tenant_id": self.request.tenant_id, "scan_id": scan_id},
                raise_on_not_found=False,
            ):
                return task
        except TaskFailedException:
            return Response(
                {"detail": "Task failed to generate compliance overview data."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        filtered_queryset = self.filter_queryset(self.get_queryset())

        all_requirements = (
            filtered_queryset.values(
                "requirement_id", "framework", "version", "description"
            )
            .distinct()
            .annotate(
                total_instances=Count("id"),
                manual_count=Count("id", filter=Q(requirement_status="MANUAL")),
            )
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
                }
            )

        serializer = self.get_serializer(requirements_summary, many=True)
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
        try:
            sample_requirement = (
                self.get_queryset().filter(compliance_id=compliance_id).first()
            )

            if sample_requirement:
                provider_type = sample_requirement.scan.provider.provider
        except Exception:
            pass

        # If we couldn't determine from database, try each provider type
        if not provider_type:
            for pt in Provider.ProviderChoices.values:
                if compliance_id in PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE.get(pt, {}):
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
            "of findings for each service, as long as there are at least one finding for that service. At least "
            "one of the `inserted_at` filters must be provided."
        ),
        filters=True,
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
class OverviewViewSet(BaseRLSViewSet):
    queryset = ComplianceOverview.objects.all()
    http_method_names = ["get"]
    ordering = ["-inserted_at"]
    # RBAC required permissions (implicit -> MANAGE_PROVIDERS enable unlimited visibility or check the visibility of
    # the provider through the provider group)
    required_permissions = []

    def get_queryset(self):
        role = get_role(self.request.user)
        providers = get_providers(role)

        def _get_filtered_queryset(model):
            if role.unlimited_visibility:
                return model.all_objects.filter(tenant_id=self.request.tenant_id)
            return model.all_objects.filter(
                tenant_id=self.request.tenant_id, scan__provider__in=providers
            )

        if self.action == "providers":
            return _get_filtered_queryset(Finding)
        elif self.action in ("findings", "findings_severity", "services"):
            return _get_filtered_queryset(ScanSummary)
        else:
            return super().get_queryset()

    def get_serializer_class(self):
        if self.action == "providers":
            return OverviewProviderSerializer
        elif self.action == "findings":
            return OverviewFindingSerializer
        elif self.action == "findings_severity":
            return OverviewSeveritySerializer
        elif self.action == "services":
            return OverviewServiceSerializer
        return super().get_serializer_class()

    def get_filterset_class(self):
        if self.action == "providers":
            return None
        elif self.action in ["findings", "findings_severity"]:
            return ScanSummaryFilter
        elif self.action == "services":
            return ServiceOverviewFilter
        return None

    @extend_schema(exclude=True)
    def list(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="GET")

    @extend_schema(exclude=True)
    def retrieve(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="GET")

    @action(detail=False, methods=["get"], url_name="providers")
    def providers(self, request):
        tenant_id = self.request.tenant_id

        latest_scan_ids = (
            Scan.all_objects.filter(tenant_id=tenant_id, state=StateChoices.COMPLETED)
            .order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
            .values_list("id", flat=True)
        )

        findings_aggregated = (
            ScanSummary.all_objects.filter(
                tenant_id=tenant_id, scan_id__in=latest_scan_ids
            )
            .values(
                "scan__provider_id",
                provider=F("scan__provider__provider"),
            )
            .annotate(
                findings_passed=Coalesce(Sum("_pass"), 0),
                findings_failed=Coalesce(Sum("fail"), 0),
                findings_muted=Coalesce(Sum("muted"), 0),
                total_findings=Coalesce(Sum("total"), 0),
            )
        )

        resources_aggregated = (
            Resource.all_objects.filter(tenant_id=tenant_id)
            .values("provider_id")
            .annotate(total_resources=Count("id"))
        )
        resource_map = {
            row["provider_id"]: row["total_resources"] for row in resources_aggregated
        }

        overview = []
        for row in findings_aggregated:
            overview.append(
                {
                    "provider": row["provider"],
                    "total_resources": resource_map.get(row["scan__provider_id"], 0),
                    "total_findings": row["total_findings"],
                    "findings_passed": row["findings_passed"],
                    "findings_failed": row["findings_failed"],
                    "findings_muted": row["findings_muted"],
                }
            )

        return Response(
            OverviewProviderSerializer(overview, many=True).data,
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["get"], url_name="findings")
    def findings(self, request):
        tenant_id = self.request.tenant_id
        queryset = self.get_queryset()
        filtered_queryset = self.filter_queryset(queryset)

        latest_scan_ids = (
            Scan.all_objects.filter(tenant_id=tenant_id, state=StateChoices.COMPLETED)
            .order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
            .values_list("id", flat=True)
        )
        filtered_queryset = filtered_queryset.filter(
            tenant_id=tenant_id, scan_id__in=latest_scan_ids
        )

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
        tenant_id = self.request.tenant_id
        queryset = self.get_queryset()
        filtered_queryset = self.filter_queryset(queryset)

        latest_scan_ids = (
            Scan.all_objects.filter(tenant_id=tenant_id, state=StateChoices.COMPLETED)
            .order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
            .values_list("id", flat=True)
        )
        filtered_queryset = filtered_queryset.filter(
            tenant_id=tenant_id, scan_id__in=latest_scan_ids
        )

        severity_counts = (
            filtered_queryset.values("severity")
            .annotate(count=Sum("total"))
            .order_by("severity")
        )

        severity_data = {sev[0]: 0 for sev in SeverityChoices}

        for item in severity_counts:
            severity_data[item["severity"]] = item["count"]

        serializer = OverviewSeveritySerializer(severity_data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_name="services")
    def services(self, request):
        tenant_id = self.request.tenant_id
        queryset = self.get_queryset()
        filtered_queryset = self.filter_queryset(queryset)

        latest_scan_ids = (
            Scan.all_objects.filter(tenant_id=tenant_id, state=StateChoices.COMPLETED)
            .order_by("provider_id", "-inserted_at")
            .distinct("provider_id")
            .values_list("id", flat=True)
        )
        filtered_queryset = filtered_queryset.filter(
            tenant_id=tenant_id, scan_id__in=latest_scan_ids
        )

        services_data = (
            filtered_queryset.values("service")
            .annotate(_pass=Sum("_pass"))
            .annotate(fail=Sum("fail"))
            .annotate(muted=Sum("muted"))
            .annotate(total=Sum("total"))
            .order_by("service")
        )

        serializer = OverviewServiceSerializer(services_data, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


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


@extend_schema_view(
    list=extend_schema(
        tags=["Lighthouse"],
        summary="List all Lighthouse configurations",
        description="Retrieve a list of all Lighthouse configurations.",
    ),
    create=extend_schema(
        tags=["Lighthouse"],
        summary="Create a new Lighthouse configuration",
        description="Create a new Lighthouse configuration with the specified details.",
    ),
    partial_update=extend_schema(
        tags=["Lighthouse"],
        summary="Partially update a Lighthouse configuration",
        description="Update certain fields of an existing Lighthouse configuration.",
    ),
    destroy=extend_schema(
        tags=["Lighthouse"],
        summary="Delete a Lighthouse configuration",
        description="Remove a Lighthouse configuration by its ID.",
    ),
    connection=extend_schema(
        tags=["Lighthouse"],
        summary="Check the connection to the OpenAI API",
        description="Verify the connection to the OpenAI API for a specific Lighthouse configuration.",
        request=None,
        responses={202: OpenApiResponse(response=TaskSerializer)},
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
