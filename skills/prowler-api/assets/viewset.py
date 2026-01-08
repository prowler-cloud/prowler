# Example: BaseRLSViewSet Implementation
# Source: api/src/backend/api/base_views.py

from django.db import transaction
from rest_framework.exceptions import NotAuthenticated

from api.db_router import MainRouter
from api.db_utils import reset_read_db_alias, rls_transaction, set_read_db_alias


class BaseRLSViewSet(BaseViewSet):
    """
    Base ViewSet with Row-Level Security (RLS) support.

    Key patterns:
    1. Wraps dispatch() in atomic transaction with RLS context
    2. Extracts tenant_id from JWT auth and sets it on request
    3. Passes tenant_id to serializer via context
    """

    def dispatch(self, request, *args, **kwargs):
        """Wrap request in RLS transaction context."""
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
        """Set RLS context from JWT tenant_id."""
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
        """Pass tenant_id to serializer context."""
        context = super().get_serializer_context()
        context["tenant_id"] = self.request.tenant_id
        return context


# Usage Example: Concrete ViewSet
class SAMLConfigurationViewSet(BaseRLSViewSet):
    """Example concrete ViewSet using BaseRLSViewSet."""

    serializer_class = SAMLConfigurationSerializer
    required_permissions = [Permissions.MANAGE_INTEGRATIONS]
    queryset = SAMLConfiguration.objects.all()

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return SAMLConfiguration.objects.none()
        return SAMLConfiguration.objects.filter(tenant=self.request.tenant_id)
