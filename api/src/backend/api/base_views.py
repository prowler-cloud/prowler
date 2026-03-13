from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from rest_framework import permissions
from rest_framework.exceptions import NotAuthenticated
from rest_framework.filters import SearchFilter
from rest_framework.permissions import SAFE_METHODS
from rest_framework_json_api import filters
from rest_framework_json_api.views import ModelViewSet

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.db_router import MainRouter, reset_read_db_alias, set_read_db_alias
from api.db_utils import POSTGRES_USER_VAR, rls_transaction
from api.filters import CustomDjangoFilterBackend
from api.models import Role, Tenant
from api.rbac.permissions import HasPermissions


class BaseViewSet(ModelViewSet):
    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
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

    def _get_request_db_alias(self, request):
        if request is None:
            return MainRouter.default_db

        read_alias = (
            MainRouter.replica_db
            if request.method in SAFE_METHODS
            and MainRouter.replica_db in settings.DATABASES
            else None
        )
        if read_alias:
            return read_alias
        return MainRouter.default_db

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
    def dispatch(self, request, *args, **kwargs):
        self.db_alias = self._get_request_db_alias(request)
        alias_token = None
        try:
            if self.db_alias != MainRouter.default_db:
                alias_token = set_read_db_alias(self.db_alias)

            if request is not None:
                request.db_alias = self.db_alias

            with transaction.atomic(using=self.db_alias):
                return super().dispatch(request, *args, **kwargs)
        finally:
            if alias_token is not None:
                reset_read_db_alias(alias_token)
            self.db_alias = MainRouter.default_db

    def initial(self, request, *args, **kwargs):
        # Ideally, this logic would be in the `.setup()` method but DRF view sets don't call it
        # https://docs.djangoproject.com/en/5.1/ref/class-based-views/base/#django.views.generic.base.View.setup
        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if tenant_id is None:
            raise NotAuthenticated("Tenant ID is not present in token")

        with rls_transaction(
            tenant_id, using=getattr(self, "db_alias", MainRouter.default_db)
        ):
            self.request.tenant_id = tenant_id
            return super().initial(request, *args, **kwargs)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["tenant_id"] = self.request.tenant_id
        return context


class BaseTenantViewset(BaseViewSet):
    def dispatch(self, request, *args, **kwargs):
        self.db_alias = self._get_request_db_alias(request)
        alias_token = None
        try:
            if self.db_alias != MainRouter.default_db:
                alias_token = set_read_db_alias(self.db_alias)

            if request is not None:
                request.db_alias = self.db_alias

            with transaction.atomic(using=self.db_alias):
                tenant = super().dispatch(request, *args, **kwargs)

            try:
                # If the request is a POST, create the admin role
                if request.method == "POST":
                    isinstance(tenant, dict) and self._create_admin_role(
                        tenant.data["id"]
                    )
            except Exception as e:
                self._handle_creation_error(e, tenant)
                raise

            return tenant
        finally:
            if alias_token is not None:
                reset_read_db_alias(alias_token)
            self.db_alias = MainRouter.default_db

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
        with rls_transaction(
            value=user_id,
            parameter=POSTGRES_USER_VAR,
            using=getattr(self, "db_alias", MainRouter.default_db),
        ):
            return super().initial(request, *args, **kwargs)


class BaseUserViewset(BaseViewSet):
    def dispatch(self, request, *args, **kwargs):
        self.db_alias = self._get_request_db_alias(request)
        alias_token = None
        try:
            if self.db_alias != MainRouter.default_db:
                alias_token = set_read_db_alias(self.db_alias)

            if request is not None:
                request.db_alias = self.db_alias

            with transaction.atomic(using=self.db_alias):
                return super().dispatch(request, *args, **kwargs)
        finally:
            if alias_token is not None:
                reset_read_db_alias(alias_token)
            self.db_alias = MainRouter.default_db

    def initial(self, request, *args, **kwargs):
        # TODO refactor after improving RLS on users
        if request.stream is not None and request.stream.method == "POST":
            return super().initial(request, *args, **kwargs)
        if request.auth is None:
            raise NotAuthenticated

        tenant_id = request.auth.get("tenant_id")
        if tenant_id is None:
            raise NotAuthenticated("Tenant ID is not present in token")

        with rls_transaction(
            tenant_id, using=getattr(self, "db_alias", MainRouter.default_db)
        ):
            self.request.tenant_id = tenant_id
            return super().initial(request, *args, **kwargs)
