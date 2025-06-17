from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from rest_framework import permissions
from rest_framework.exceptions import NotAuthenticated
from rest_framework.filters import SearchFilter
from rest_framework_json_api import filters
from rest_framework_json_api.views import ModelViewSet
from rest_framework_simplejwt.authentication import JWTAuthentication

from api.db_router import MainRouter
from api.db_utils import POSTGRES_USER_VAR, rls_transaction
from api.filters import CustomDjangoFilterBackend
from api.models import Role, Tenant
from api.rbac.permissions import HasPermissions


class BaseViewSet(ModelViewSet):
    _rls_ctx = None

    authentication_classes = [JWTAuthentication]
    required_permissions = []
    permission_classes = [permissions.IsAuthenticated, HasPermissions]
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

    def initial(self, request, *args, **kwargs):
        """
        Sets required_permissions before permissions are checked.
        """
        self.set_required_permissions()
        super().initial(request, *args, **kwargs)

    def set_required_permissions(self):
        """This is an abstract method that must be implemented by subclasses."""
        NotImplemented

    def get_queryset(self):
        raise NotImplementedError

    def finalize_response(self, request, response, *args, **kwargs):
        try:
            return super().finalize_response(request, response, *args, **kwargs)
        finally:
            if self._rls_ctx:
                self._rls_ctx.__exit__(None, None, None)
                self._rls_ctx = None


class BaseRLSViewSet(BaseViewSet):
    def initial(self, request, *args, **kwargs):
        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if not tenant_id:
            raise NotAuthenticated("Tenant ID missing in JWT")

        self._rls_ctx = rls_transaction(tenant_id)
        self._rls_ctx.__enter__()

        self.request.tenant_id = tenant_id
        return super().initial(request, *args, **kwargs)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["tenant_id"] = self.request.tenant_id
        return context


class BaseTenantViewset(BaseViewSet):
    def dispatch(self, request, *args, **kwargs):
        with transaction.atomic():
            tenant = super().dispatch(request, *args, **kwargs)

        try:
            # If the request is a POST, create the admin role
            if request.method == "POST":
                isinstance(tenant, dict) and self._create_admin_role(tenant.data["id"])
        except Exception as e:
            self._handle_creation_error(e, tenant)
            raise

        return tenant

    def _create_admin_role(self, tenant_id):
        Role.objects.using(MainRouter.admin_db).create(
            name="admin",
            tenant_id=tenant_id,
            manage_users=True,
            manage_account=True,
            manage_billing=True,
            manage_providers=True,
            manage_integrations=True,
            manage_scans=True,
            unlimited_visibility=True,
        )

    def _handle_creation_error(self, error, tenant):
        if tenant.data.get("id"):
            try:
                Tenant.objects.using(MainRouter.admin_db).filter(
                    id=tenant.data["id"]
                ).delete()
            except ObjectDoesNotExist:
                pass  # Tenant might not exist, handle gracefully

    def initial(self, request, *args, **kwargs):
        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if tenant_id is None:
            raise NotAuthenticated("Tenant ID is not present in token")

        user_id = str(request.user.id)

        self._rls_ctx = rls_transaction(value=user_id, parameter=POSTGRES_USER_VAR)
        self._rls_ctx.__enter__()

        return super().initial(request, *args, **kwargs)


class BaseUserViewset(BaseViewSet):
    def initial(self, request, *args, **kwargs):
        if request.stream is not None and request.stream.method == "POST":
            return super().initial(request, *args, **kwargs)
        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if tenant_id is None:
            raise NotAuthenticated("Tenant ID is not present in token")

        self._rls_ctx = rls_transaction(tenant_id)
        self._rls_ctx.__enter__()

        self.request.tenant_id = tenant_id
        return super().initial(request, *args, **kwargs)
