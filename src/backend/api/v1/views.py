from django.conf import settings as django_settings
from django.db.models import F
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from drf_spectacular.settings import spectacular_settings
from drf_spectacular.utils import extend_schema, extend_schema_view
from drf_spectacular.views import SpectacularAPIView
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.generics import get_object_or_404
from rest_framework_json_api.views import Response
from celery.result import AsyncResult

from api.base_views import BaseRLSViewSet, BaseViewSet
from api.filters import ProviderFilter, TenantFilter, ScanFilter, TaskFilter
from api.models import Provider, Scan, Task
from api.rls import Tenant
from api.v1.serializers import (
    ProviderSerializer,
    ProviderCreateSerializer,
    ProviderUpdateSerializer,
    TenantSerializer,
    TaskSerializer,
    DelayedTaskSerializer,
    ScanSerializer,
    ScanCreateSerializer,
    ScanUpdateSerializer,
)
from tasks.tasks import check_provider_connection_task, delete_provider_task

CACHE_DECORATOR = cache_control(
    max_age=django_settings.CACHE_MAX_AGE,
    stale_while_revalidate=django_settings.CACHE_STALE_WHILE_REVALIDATE,
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
        return super().get(request, *args, **kwargs)


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
class TenantViewSet(BaseViewSet):
    queryset = Tenant.objects.all()
    serializer_class = TenantSerializer
    http_method_names = ["get", "post", "patch", "delete"]
    filterset_class = TenantFilter
    search_fields = ["name"]
    ordering = ["inserted_at"]
    ordering_fields = ["name", "inserted_at", "updated_at"]

    def get_queryset(self):
        return Tenant.objects.all()


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
        responses={202: DelayedTaskSerializer},
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ProviderViewSet(BaseRLSViewSet):
    queryset = Provider.objects.all()
    serializer_class = ProviderSerializer
    http_method_names = ["get", "post", "patch", "delete"]
    filterset_class = ProviderFilter
    search_fields = ["provider", "provider_id", "alias"]
    ordering = ["inserted_at"]
    ordering_fields = [
        "provider",
        "provider_id",
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
            return DelayedTaskSerializer
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
        responses={202: DelayedTaskSerializer},
    )
    @action(detail=True, methods=["post"], url_name="connection")
    def connection(self, request, pk=None):
        get_object_or_404(Provider, pk=pk)
        task = check_provider_connection_task.delay(
            provider_id=pk, tenant_id=request.headers.get("X-Tenant-ID")
        )
        serializer = DelayedTaskSerializer(task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse("task-detail", kwargs={"pk": task.id})
            },
        )

    def destroy(self, request, *args, pk=None, **kwargs):
        get_object_or_404(Provider, pk=pk)
        task = delete_provider_task.delay(
            provider_id=pk, tenant_id=request.headers.get("X-Tenant-ID")
        )
        serializer = DelayedTaskSerializer(task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse("task-detail", kwargs={"pk": task.id})
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
    create=extend_schema(
        summary="Trigger a manual scan",
        description=(
            "Trigger a manual scan by providing the required scan details. "
            "If `scanner_args` are not provided, the system will automatically use the default settings "
            "from the associated provider. If you do provide `scanner_args`, these settings will be "
            "merged with the provider's defaults. This means that your provided settings will override "
            "the defaults only where they conflict, while the rest of the default settings will remain intact."
        ),
    ),
    partial_update=extend_schema(
        summary="Partially update a scan",
        description="Update certain fields of an existing scan without affecting other fields.",
        request=ScanUpdateSerializer,
        responses={200: ScanSerializer},
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ScanViewSet(BaseRLSViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    http_method_names = ["get", "post", "patch"]
    filterset_class = ScanFilter
    ordering = ["inserted_at"]
    ordering_fields = [
        "provider_id",
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
            return ScanCreateSerializer
        elif self.action == "partial_update":
            return ScanUpdateSerializer
        return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        scan = serializer.save()

        # TODO: Run scan through task and return task info here
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse("scan-detail", kwargs={"pk": scan.id})
            },
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
        read_serializer = ScanSerializer(
            instance, context=self.get_serializer_context()
        )
        return Response(data=read_serializer.data, status=status.HTTP_200_OK)


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
        responses={202: DelayedTaskSerializer},
    ),
)
class TaskViewSet(BaseRLSViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    http_method_names = ["get", "delete"]
    filterset_class = TaskFilter
    search_fields = ["name"]
    ordering = ["inserted_at"]
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
        serializer = DelayedTaskSerializer(task_instance)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse("task-detail", kwargs={"pk": task.id})
            },
        )
