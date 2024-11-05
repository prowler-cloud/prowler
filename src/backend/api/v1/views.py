from celery.result import AsyncResult
from django.conf import settings as django_settings
from django.contrib.postgres.search import SearchQuery
from django.db import transaction
from django.db.models import F, Q
from django.db.models import Prefetch
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from drf_spectacular.settings import spectacular_settings
from drf_spectacular.utils import OpenApiTypes
from drf_spectacular.utils import (
    extend_schema,
    extend_schema_view,
    OpenApiParameter,
    OpenApiResponse,
)
from drf_spectacular.views import SpectacularAPIView
from rest_framework import status, permissions
from rest_framework.decorators import action
from rest_framework.exceptions import (
    MethodNotAllowed,
    NotFound,
    PermissionDenied,
    ValidationError,
)
from rest_framework.generics import get_object_or_404, GenericAPIView
from rest_framework_json_api.views import Response
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.exceptions import TokenError

from api.base_views import BaseTenantViewset, BaseRLSViewSet, BaseViewSet
from api.db_router import MainRouter
from api.filters import (
    ProviderFilter,
    TenantFilter,
    MembershipFilter,
    ScanFilter,
    TaskFilter,
    ResourceFilter,
    FindingFilter,
    ProviderSecretFilter,
    InvitationFilter,
)
from api.models import (
    User,
    Membership,
    Provider,
    Scan,
    Task,
    Resource,
    Finding,
    ProviderSecret,
    Invitation,
)
from api.rls import Tenant
from api.utils import validate_invitation
from api.uuid_utils import datetime_to_uuid7
from api.v1.serializers import (
    TokenSerializer,
    TokenRefreshSerializer,
    UserSerializer,
    UserCreateSerializer,
    UserUpdateSerializer,
    MembershipSerializer,
    ProviderSerializer,
    ProviderCreateSerializer,
    ProviderUpdateSerializer,
    TenantSerializer,
    TaskSerializer,
    ScanSerializer,
    ScanCreateSerializer,
    ScanUpdateSerializer,
    ResourceSerializer,
    FindingSerializer,
    ProviderSecretSerializer,
    ProviderSecretUpdateSerializer,
    ProviderSecretCreateSerializer,
    InvitationSerializer,
    InvitationCreateSerializer,
    InvitationUpdateSerializer,
    InvitationAcceptSerializer,
)
from tasks.tasks import (
    check_provider_connection_task,
    delete_provider_task,
    perform_scan_task,
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
    resource_name = "Token"
    serializer_class = TokenSerializer
    http_method_names = ["post"]

    def post(self, request):
        serializer = TokenSerializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(
            data={"type": "Token", "attributes": serializer.validated_data},
            status=status.HTTP_200_OK,
        )


@extend_schema(
    tags=["Token"],
    summary="Refresh a token",
    description="Refresh an access token by providing a valid refresh token. Former refresh tokens are invalidated "
    "when a new one is issued.",
)
class CustomTokenRefreshView(GenericAPIView):
    resource_name = "TokenRefresh"
    serializer_class = TokenRefreshSerializer
    http_method_names = ["post"]

    def post(self, request):
        serializer = TokenRefreshSerializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(
            data={"type": "TokenRefresh", "attributes": serializer.validated_data},
            status=status.HTTP_200_OK,
        )


@extend_schema(exclude=True)
class SchemaView(SpectacularAPIView):
    serializer_class = None

    def get(self, request, *args, **kwargs):
        spectacular_settings.TITLE = "Prowler API"
        spectacular_settings.VERSION = "1.0.0"
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
                "name": "Provider",
                "description": "Endpoints for managing providers (AWS, GCP, Azure, etc...).",
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
                "name": "Task",
                "description": "Endpoints for task management, allowing retrieval of task status and "
                "revoking tasks that have not started.",
            },
            {
                "name": "Invitation",
                "description": "Endpoints for tenant invitations management, allowing retrieval and filtering of "
                "invitations, creating new invitations, accepting and revoking them.",
            },
        ]
        return super().get(request, *args, **kwargs)


@extend_schema_view(
    retrieve=extend_schema(
        summary="Retrieve a user's information",
        description="Fetch detailed information about an authenticated user. It only allows using your own user ID.",
    ),
    create=extend_schema(
        summary="Register a new user",
        description="Create a new user account by providing the necessary registration details.",
    ),
    partial_update=extend_schema(
        summary="Update the current user's information",
        description="Partially update the authenticated user's information.",
    ),
    destroy=extend_schema(
        summary="Delete the current user's account",
        description="Remove the authenticated user's account from the system.",
    ),
    me=extend_schema(
        summary="Retrieve the current user's information",
        description="Fetch detailed information about the authenticated user.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
class UserViewSet(BaseViewSet):
    serializer_class = UserSerializer
    http_method_names = ["get", "post", "patch", "delete"]
    ordering = ["id"]
    ordering_fields = []

    def get_queryset(self):
        return User.objects.filter(id=self.request.user.id)

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

    @extend_schema(exclude=True)
    def list(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="GET")

    def retrieve(self, request, *args, **kwargs):
        if kwargs["pk"] != str(request.user.id):
            raise NotFound(detail="User was not found.")
        return super().retrieve(request, *args, **kwargs)

    @action(detail=False, methods=["get"], url_name="me")
    def me(self, request):
        user = self.get_queryset().first()
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

    def partial_update(self, request, *args, **kwargs):
        if kwargs["pk"] != str(request.user.id):
            raise NotFound(detail="User was not found.")
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        if kwargs["pk"] != str(request.user.id):
            raise NotFound(detail="User was not found.")
        return super().destroy(request, *args, **kwargs)


@extend_schema_view(
    list=extend_schema(
        summary="List all tenants",
        description="Retrieve a list of all tenants with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        summary="Retrieve data from a tenant",
        description="Fetch detailed information about a specific tenant by their ID.",
    ),
    create=extend_schema(
        summary="Create a new tenant",
        description="Add a new tenant to the system by providing the required tenant details.",
    ),
    partial_update=extend_schema(
        summary="Partially update a tenant",
        description="Update certain fields of an existing tenant's information without affecting other fields.",
    ),
    destroy=extend_schema(
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

    # TODO: Add invite functionality

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


@extend_schema_view(
    list=extend_schema(
        summary="List all providers",
        description="Retrieve a list of all providers with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        summary="Retrieve data from a provider",
        description="Fetch detailed information about a specific provider by their ID.",
    ),
    create=extend_schema(
        summary="Create a new provider",
        description="Add a new provider to the system by providing the required provider details.",
    ),
    partial_update=extend_schema(
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
        get_object_or_404(Provider, pk=pk)
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
        summary="List all scans",
        description="Retrieve a list of all scans with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        summary="Retrieve data from a specific scan",
        description="Fetch detailed information about a specific scan by its ID.",
    ),
    partial_update=extend_schema(
        summary="Partially update a scan",
        description="Update certain fields of an existing scan without affecting other fields.",
    ),
    create=extend_schema(
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
            task = perform_scan_task.delay(
                tenant_id=request.tenant_id,
                scan_id=str(scan.id),
                provider_id=str(scan.provider_id),
                checks_to_execute=scan.scanner_args.get("checks_to_execute"),
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
        summary="List all tasks",
        description="Retrieve a list of all tasks with options for filtering by name, state, and other criteria.",
    ),
    retrieve=extend_schema(
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
        summary="List all resources",
        description="Retrieve a list of all resources with options for filtering by various criteria. Resources are "
        "objects that are discovered by Prowler. They can be anything from a single host to a whole VPC.",
    ),
    retrieve=extend_schema(
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
