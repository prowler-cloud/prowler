import uuid

from django.db import connection, transaction
from rest_framework import permissions
from rest_framework.exceptions import NotAuthenticated
from rest_framework.filters import SearchFilter
from rest_framework_json_api import filters
from rest_framework_json_api.serializers import ValidationError
from rest_framework_json_api.views import ModelViewSet
from rest_framework_simplejwt.authentication import JWTAuthentication

from api.filters import CustomDjangoFilterBackend


class BaseViewSet(ModelViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [
        filters.QueryParameterValidationFilter,
        filters.OrderingFilter,
        CustomDjangoFilterBackend,
        SearchFilter,
    ]

    filterset_fields = []
    search_fields = []

    ordering_fields = "__all__"
    ordering = ["id"]

    def get_queryset(self):
        raise NotImplementedError


class BaseRLSViewSet(BaseViewSet):
    def dispatch(self, request, *args, **kwargs):
        with transaction.atomic():
            return super().dispatch(request, *args, **kwargs)

    def initial(self, request, *args, **kwargs):
        # Ideally, this logic would be in the `.setup()` method but DRF view sets don't call it
        # https://docs.djangoproject.com/en/5.1/ref/class-based-views/base/#django.views.generic.base.View.setup
        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if tenant_id is None:
            raise NotAuthenticated("Tenant ID is not present in token")

        try:
            uuid.UUID(tenant_id)
        except ValueError:
            raise ValidationError("Tenant ID must be a valid UUID")

        with connection.cursor() as cursor:
            cursor.execute(f"SELECT set_config('api.tenant_id', '{tenant_id}', TRUE);")
            self.request.tenant_id = tenant_id
            return super().initial(request, *args, **kwargs)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["tenant_id"] = self.request.tenant_id
        return context


class BaseTenantViewset(BaseViewSet):
    def dispatch(self, request, *args, **kwargs):
        with transaction.atomic():
            return super().dispatch(request, *args, **kwargs)

    def initial(self, request, *args, **kwargs):
        if (
            request.resolver_match.url_name != "tenant-detail"
            and request.method != "DELETE"
        ):
            user_id = str(request.user.id)

            with connection.cursor() as cursor:
                cursor.execute(f"SELECT set_config('api.user_id', '{user_id}', TRUE);")
                return super().initial(request, *args, **kwargs)

        # TODO: DRY this when we have time
        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if tenant_id is None:
            raise NotAuthenticated("Tenant ID is not present in token")

        try:
            uuid.UUID(tenant_id)
        except ValueError:
            raise ValidationError("Tenant ID must be a valid UUID")

        with connection.cursor() as cursor:
            cursor.execute(f"SELECT set_config('api.tenant_id', '{tenant_id}', TRUE);")
            self.request.tenant_id = tenant_id
            return super().initial(request, *args, **kwargs)


class BaseUserViewset(BaseViewSet):
    def dispatch(self, request, *args, **kwargs):
        with transaction.atomic():
            return super().dispatch(request, *args, **kwargs)

    def initial(self, request, *args, **kwargs):
        # TODO refactor after improving RLS on users
        if request.stream is not None and request.stream.method == "POST":
            return super().initial(request, *args, **kwargs)
        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if tenant_id is None:
            raise NotAuthenticated("Tenant ID is not present in token")

        try:
            uuid.UUID(tenant_id)
        except ValueError:
            raise ValidationError("Tenant ID must be a valid UUID")

        with connection.cursor() as cursor:
            cursor.execute(f"SELECT set_config('api.tenant_id', '{tenant_id}', TRUE);")
            self.request.tenant_id = tenant_id
            return super().initial(request, *args, **kwargs)
