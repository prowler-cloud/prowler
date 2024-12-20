from celery.result import AsyncResult
from django.conf import settings as django_settings
from django.contrib.postgres.aggregates import ArrayAgg
from django.contrib.postgres.search import SearchQuery
from django.db import transaction
from django.db.models import Count, F, OuterRef, Prefetch, Q, Subquery, Sum
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from drf_spectacular.settings import spectacular_settings
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    OpenApiTypes,
    extend_schema,
    extend_schema_view,
)
from drf_spectacular.views import SpectacularAPIView
from rest_framework import permissions, status
from rest_framework.decorators import action
from rest_framework.exceptions import (
    MethodNotAllowed,
    NotFound,
    PermissionDenied,
    ValidationError,
)
from rest_framework.generics import GenericAPIView, get_object_or_404
from rest_framework_json_api.views import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from tasks.beat import schedule_provider_scan
from tasks.tasks import (
    check_provider_connection_task,
    delete_provider_task,
    delete_tenant_task,
    perform_scan_summary_task,
    perform_scan_task,
)

from api.base_views import BaseRLSViewSet, BaseTenantViewset, BaseUserViewset
from api.db_router import MainRouter
from api.filters import (
    ComplianceOverviewFilter,
    FindingFilter,
    InvitationFilter,
    MembershipFilter,
    ProviderFilter,
    ProviderGroupFilter,
    ProviderSecretFilter,
    ResourceFilter,
    ScanFilter,
    ScanSummaryFilter,
    TaskFilter,
    TenantFilter,
    UserFilter,
)
from api.models import (
    ComplianceOverview,
    Finding,
    Invitation,
    Membership,
    Provider,
    ProviderGroup,
    ProviderGroupMembership,
    ProviderSecret,
    Resource,
    Scan,
    ScanSummary,
    SeverityChoices,
    StateChoices,
    StatusChoices,
    Task,
    User,
)
from api.pagination import ComplianceOverviewPagination
from api.rls import Tenant
from api.utils import validate_invitation
from api.uuid_utils import datetime_to_uuid7
from api.v1.serializers import (
    ComplianceOverviewFullSerializer,
    ComplianceOverviewSerializer,
    FindingDynamicFilterSerializer,
    FindingSerializer,
    InvitationAcceptSerializer,
    InvitationCreateSerializer,
    InvitationSerializer,
    InvitationUpdateSerializer,
    MembershipSerializer,
    OverviewFindingSerializer,
    OverviewProviderSerializer,
    OverviewSeveritySerializer,
    ProviderCreateSerializer,
    ProviderGroupMembershipUpdateSerializer,
    ProviderGroupSerializer,
    ProviderGroupUpdateSerializer,
    ProviderSecretCreateSerializer,
    ProviderSecretSerializer,
    ProviderSecretUpdateSerializer,
    ProviderSerializer,
    ProviderUpdateSerializer,
    ResourceSerializer,
    ScanCreateSerializer,
    ScanSerializer,
    ScanUpdateSerializer,
    ScheduleDailyCreateSerializer,
    TaskSerializer,
    TenantSerializer,
    TokenRefreshSerializer,
    TokenSerializer,
    UserCreateSerializer,
    UserSerializer,
    UserUpdateSerializer,
)

CACHE_DECORATOR = cache_control(
    max_age=django_settings.CACHE_MAX_AGE,
    stale_while_revalidate=django_settings.CACHE_STALE_WHILE_REVALIDATE,
)


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


@extend_schema(exclude=True)
class SchemaView(SpectacularAPIView):
    serializer_class = None

    def get(self, request, *args, **kwargs):
        spectacular_settings.TITLE = "Prowler API"
        spectacular_settings.VERSION = "1.1.1"
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
        ]
        return super().get(request, *args, **kwargs)


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
        summary="Delete a user account",
        description="Remove a user account from the system.",
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

    def get_queryset(self):
        # If called during schema generation, return an empty queryset
        if getattr(self, "swagger_fake_view", False):
            return User.objects.none()
        return User.objects.filter(membership__tenant__id=self.request.tenant_id)

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
            invitation.state = Invitation.State.ACCEPTED
            invitation.save(using=MainRouter.admin_db)
        return Response(data=UserSerializer(user).data, status=status.HTTP_201_CREATED)


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

    def get_queryset(self):
        return Tenant.objects.all()

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

    def get_queryset(self):
        user = self.request.user
        return Membership.objects.filter(user_id=user.id)


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
    http_method_names = ["get", "post", "patch", "put", "delete"]
    ordering = ["inserted_at"]

    def get_queryset(self):
        return ProviderGroup.objects.prefetch_related("providers")

    def get_serializer_class(self):
        if self.action == "partial_update":
            return ProviderGroupUpdateSerializer
        elif self.action == "providers":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
            return ProviderGroupMembershipUpdateSerializer
        return super().get_serializer_class()

    @extend_schema(
        tags=["Provider Group"],
        summary="Add providers to a provider group",
        description="Add one or more providers to an existing provider group.",
        request=ProviderGroupMembershipUpdateSerializer,
        responses={200: OpenApiResponse(response=ProviderGroupSerializer)},
    )
    @action(detail=True, methods=["put"], url_name="providers")
    def providers(self, request, pk=None):
        provider_group = self.get_object()

        # Validate input data
        serializer = self.get_serializer_class()(
            data=request.data,
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)

        provider_ids = serializer.validated_data["provider_ids"]

        # Update memberships
        ProviderGroupMembership.objects.filter(
            provider_group=provider_group, tenant_id=request.tenant_id
        ).delete()

        provider_group_memberships = [
            ProviderGroupMembership(
                tenant_id=self.request.tenant_id,
                provider_group=provider_group,
                provider_id=provider_id,
            )
            for provider_id in provider_ids
        ]

        ProviderGroupMembership.objects.bulk_create(
            provider_group_memberships, ignore_conflicts=True
        )

        # Return the updated provider group with providers
        provider_group.refresh_from_db()
        self.response_serializer_class = ProviderGroupSerializer
        response_serializer = ProviderGroupSerializer(
            provider_group, context=self.get_serializer_context()
        )
        return Response(data=response_serializer.data, status=status.HTTP_200_OK)


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

    def get_queryset(self):
        return Provider.objects.all()

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
                provider_id=pk, tenant_id=request.tenant_id
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

        with transaction.atomic():
            task = delete_provider_task.delay(
                provider_id=pk, tenant_id=request.tenant_id
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

    def get_queryset(self):
        return Scan.objects.all()

    def get_serializer_class(self):
        if self.action == "create":
            if hasattr(self, "response_serializer_class"):
                return self.response_serializer_class
            return ScanCreateSerializer
        elif self.action == "partial_update":
            return ScanUpdateSerializer
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

    def create(self, request, *args, **kwargs):
        input_serializer = self.get_serializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            scan = input_serializer.save()
        with transaction.atomic():
            task = perform_scan_task.apply_async(
                kwargs={
                    "tenant_id": request.tenant_id,
                    "scan_id": str(scan.id),
                    "provider_id": str(scan.provider_id),
                    # Disabled for now
                    # checks_to_execute=scan.scanner_args.get("checks_to_execute"),
                },
                link=perform_scan_summary_task.si(
                    tenant_id=request.tenant_id,
                    scan_id=str(scan.id),
                ),
            )

        scan.task_id = task.id
        scan.save(update_fields=["task_id"])

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

    def get_queryset(self):
        return Task.objects.annotate(
            name=F("task_runner_task__task_name"), state=F("task_runner_task__status")
        )

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

    def get_queryset(self):
        queryset = Resource.objects.all()
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
        responses={201: OpenApiResponse(response=MembershipSerializer)},
        filters=True,
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class FindingViewSet(BaseRLSViewSet):
    queryset = Finding.objects.all()
    serializer_class = FindingSerializer
    prefetch_for_includes = {
        "__all__": [],
        "resources": [
            Prefetch("resources", queryset=Resource.objects.select_related("findings"))
        ],
        "scan": [Prefetch("scan", queryset=Scan.objects.select_related("findings"))],
    }
    http_method_names = ["get"]
    filterset_class = FindingFilter
    ordering = ["-id"]
    ordering_fields = [
        "id",
        "status",
        "severity",
        "check_id",
        "inserted_at",
        "updated_at",
    ]

    def inserted_at_to_uuidv7(self, inserted_at):
        if inserted_at is None:
            return None
        return datetime_to_uuid7(inserted_at)

    def get_serializer_class(self):
        if self.action == "findings_services_regions":
            return FindingDynamicFilterSerializer

        return super().get_serializer_class()

    def get_queryset(self):
        queryset = Finding.objects.all()
        search_value = self.request.query_params.get("filter[search]", None)

        if search_value:
            # Django's ORM will build a LEFT JOIN and OUTER JOIN on any "through" tables, resulting in duplicates
            # The duplicates then require a `distinct` query
            search_query = SearchQuery(
                search_value, config="simple", search_type="plain"
            )
            queryset = queryset.filter(
                Q(impact_extended__contains=search_value)
                | Q(status_extended__contains=search_value)
                | Q(check_id=search_value)
                | Q(check_id__icontains=search_value)
                | Q(text_search=search_query)
                | Q(resources__uid=search_value)
                | Q(resources__name=search_value)
                | Q(resources__region=search_value)
                | Q(resources__service=search_value)
                | Q(resources__type=search_value)
                | Q(resources__uid__contains=search_value)
                | Q(resources__name__contains=search_value)
                | Q(resources__region__contains=search_value)
                | Q(resources__service__contains=search_value)
                | Q(resources__tags__text_search=search_query)
                | Q(resources__text_search=search_query)
            ).distinct()

        return queryset

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

    def get_queryset(self):
        return ProviderSecret.objects.all()

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

    def get_queryset(self):
        return Invitation.objects.all()

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
        return Invitation.objects.all()

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
        invitation.state = Invitation.State.ACCEPTED
        invitation.save(using=MainRouter.admin_db)

        self.response_serializer_class = MembershipSerializer
        membership_serializer = self.get_serializer(membership)
        return Response(data=membership_serializer.data, status=status.HTTP_201_CREATED)


@extend_schema_view(
    list=extend_schema(
        tags=["Compliance Overview"],
        summary="List compliance overviews for a scan",
        description="Retrieve an overview of all the compliance in a given scan. If no region filters are provided, the"
        " region with the most fails will be returned by default.",
        parameters=[
            OpenApiParameter(
                name="filter[scan_id]",
                required=True,
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.QUERY,
                description="Related scan ID.",
            ),
        ],
    ),
    retrieve=extend_schema(
        tags=["Compliance Overview"],
        summary="Retrieve data from a specific compliance overview",
        description="Fetch detailed information about a specific compliance overview by its ID, including detailed "
        "requirement information and check's status.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ComplianceOverviewViewSet(BaseRLSViewSet):
    pagination_class = ComplianceOverviewPagination
    queryset = ComplianceOverview.objects.all()
    serializer_class = ComplianceOverviewSerializer
    filterset_class = ComplianceOverviewFilter
    http_method_names = ["get"]
    search_fields = ["compliance_id"]
    ordering = ["compliance_id"]
    ordering_fields = ["inserted_at", "compliance_id", "framework", "region"]

    def get_queryset(self):
        if self.action == "retrieve":
            return ComplianceOverview.objects.all()

        base_queryset = self.filter_queryset(ComplianceOverview.objects.all())

        max_failed_ids = (
            base_queryset.filter(compliance_id=OuterRef("compliance_id"))
            .order_by("-requirements_failed")
            .values("id")[:1]
        )

        queryset = base_queryset.filter(id__in=Subquery(max_failed_ids)).order_by(
            "compliance_id"
        )

        return queryset

    def get_serializer_class(self):
        if self.action == "retrieve":
            return ComplianceOverviewFullSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        if not request.query_params.get("filter[scan_id]"):
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
        return super().list(request, *args, **kwargs)


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
)
@method_decorator(CACHE_DECORATOR, name="list")
class OverviewViewSet(BaseRLSViewSet):
    queryset = ComplianceOverview.objects.all()
    http_method_names = ["get"]
    ordering = ["-id"]

    def get_queryset(self):
        if self.action == "providers":
            return Finding.objects.all()
        elif self.action == "findings":
            return ScanSummary.objects.all()
        elif self.action == "findings_severity":
            return ScanSummary.objects.all()
        else:
            return super().get_queryset()

    def get_serializer_class(self):
        if self.action == "providers":
            return OverviewProviderSerializer
        elif self.action == "findings":
            return OverviewFindingSerializer
        elif self.action == "findings_severity":
            return OverviewSeveritySerializer
        return super().get_serializer_class()

    def get_filterset_class(self):
        if self.action == "providers":
            return None
        elif self.action in ["findings", "findings_severity"]:
            return ScanSummaryFilter
        return None

    @extend_schema(exclude=True)
    def list(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="GET")

    @extend_schema(exclude=True)
    def retrieve(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="GET")

    @action(detail=False, methods=["get"], url_name="providers")
    def providers(self, request):
        # Subquery to get the most recent finding for each uid
        latest_finding_ids = (
            Finding.objects.filter(
                uid=OuterRef("uid"), scan__provider=OuterRef("scan__provider")
            )
            .order_by("-id")  # Most recent by id
            .values("id")[:1]
        )

        # Filter findings to only include the most recent for each uid
        recent_findings = Finding.objects.filter(id__in=Subquery(latest_finding_ids))

        # Aggregate findings by provider
        findings_aggregated = (
            recent_findings.values("scan__provider__provider")
            .annotate(
                findings_passed=Count("id", filter=Q(status=StatusChoices.PASS.value)),
                findings_failed=Count("id", filter=Q(status=StatusChoices.FAIL.value)),
                findings_manual=Count(
                    "id", filter=Q(status=StatusChoices.MANUAL.value)
                ),
                total_findings=Count("id"),
            )
            .order_by("-findings_failed")
        )

        # Aggregate total resources by provider
        resources_aggregated = Resource.objects.values("provider__provider").annotate(
            total_resources=Count("id")
        )

        # Combine findings and resources data
        overview = []
        for findings in findings_aggregated:
            provider = findings["scan__provider__provider"]
            total_resources = next(
                (
                    res["total_resources"]
                    for res in resources_aggregated
                    if res["provider__provider"] == provider
                ),
                0,
            )
            overview.append(
                {
                    "provider": provider,
                    "total_resources": total_resources,
                    "total_findings": findings["total_findings"],
                    "findings_passed": findings["findings_passed"],
                    "findings_failed": findings["findings_failed"],
                    "findings_manual": findings["findings_manual"],
                }
            )

        serializer = OverviewProviderSerializer(overview, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_name="findings")
    def findings(self, request):
        queryset = self.get_queryset()
        filtered_queryset = self.filter_queryset(queryset)

        latest_scan_subquery = (
            Scan.objects.filter(
                state=StateChoices.COMPLETED, provider_id=OuterRef("scan__provider_id")
            )
            .order_by("-id")
            .values("id")[:1]
        )

        annotated_queryset = filtered_queryset.annotate(
            latest_scan_id=Subquery(latest_scan_subquery)
        )

        filtered_queryset = annotated_queryset.filter(scan_id=F("latest_scan_id"))

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
        queryset = self.get_queryset()
        filtered_queryset = self.filter_queryset(queryset)

        latest_scan_subquery = (
            Scan.objects.filter(
                state=StateChoices.COMPLETED, provider_id=OuterRef("scan__provider_id")
            )
            .order_by("-id")
            .values("id")[:1]
        )

        annotated_queryset = filtered_queryset.annotate(
            latest_scan_id=Subquery(latest_scan_subquery)
        )

        filtered_queryset = annotated_queryset.filter(scan_id=F("latest_scan_id"))

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
