from django.conf import settings as django_settings
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from drf_spectacular.settings import spectacular_settings
from drf_spectacular.utils import extend_schema, extend_schema_view
from drf_spectacular.views import SpectacularAPIView

from api.filters import TenantFilter
from api.models import Tenant
from api.serializers import TenantSerializer
from api.views.base_views import BaseViewSet

CACHE_DECORATOR = cache_control(
    max_age=django_settings.CACHE_MAX_AGE,
    stale_while_revalidate=django_settings.CACHE_STALE_WHILE_REVALIDATE,
)


@extend_schema(exclude=True)
class SchemaView(SpectacularAPIView):
    serializer_class = None

    def get(self, request, *args, **kwargs):
        spectacular_settings.TITLE = "Prowler RESTful API"
        spectacular_settings.VERSION = "1.0.0"
        spectacular_settings.DESCRIPTION = (
            "Prowler RESTful API specification.\n\nThis file is auto-generated."
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
