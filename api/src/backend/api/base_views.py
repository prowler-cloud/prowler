from django.core.exceptions import ObjectDoesNotExist
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


class BaseRLSViewSet(BaseViewSet):
    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)

        # Ideally, this logic would be in the `.setup()` method but DRF view sets don't call it
        # https://docs.djangoproject.com/en/5.1/ref/class-based-views/base/#django.views.generic.base.View.setup
        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if tenant_id is None:
            raise NotAuthenticated("Tenant ID is not present in token")

        self.request.tenant_id = tenant_id

        self._rls_cm = rls_transaction(tenant_id)
        self._rls_cm.__enter__()

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)

        if hasattr(self, "_rls_cm"):
            self._rls_cm.__exit__(None, None, None)
            del self._rls_cm

        return response

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["tenant_id"] = self.request.tenant_id
        return context


class BaseTenantViewset(BaseViewSet):
    def dispatch(self, request, *args, **kwargs):
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
        super().initial(request, *args, **kwargs)

        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if tenant_id is None:
            raise NotAuthenticated("Tenant ID is not present in token")

        user_id = str(request.user.id)

        self._rls_cm = rls_transaction(value=user_id, parameter=POSTGRES_USER_VAR)
        self._rls_cm.__enter__()

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)

        if hasattr(self, "_rls_cm"):
            self._rls_cm.__exit__(None, None, None)
            del self._rls_cm

        return response


class BaseUserViewset(BaseViewSet):
    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)

        # TODO refactor after improving RLS on users
        if request.stream is not None and request.stream.method == "POST":
            return
        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if tenant_id is None:
            raise NotAuthenticated("Tenant ID is not present in token")

        self.request.tenant_id = tenant_id

        self._rls_cm = rls_transaction(tenant_id)
        self._rls_cm.__enter__()

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)

        if hasattr(self, "_rls_cm"):
            self._rls_cm.__exit__(None, None, None)
            del self._rls_cm

        return response
