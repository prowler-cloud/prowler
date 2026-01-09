# Example: RBAC (Role-Based Access Control) Implementation
# Source: api/src/backend/api/rbac/permissions.py, api/src/backend/api/v1/views.py

from enum import Enum
from typing import Optional

from django.db.models import QuerySet
from rest_framework.permissions import BasePermission

from api.db_router import MainRouter
from api.models import Provider, Role, User

# =============================================================================
# 1. Permissions Enum - All available permission flags
# =============================================================================


class Permissions(Enum):
    """
    Permission flags stored as boolean columns on Role model.
    Used with required_permissions on ViewSets.
    """

    MANAGE_USERS = "manage_users"
    MANAGE_ACCOUNT = "manage_account"
    MANAGE_BILLING = "manage_billing"
    MANAGE_PROVIDERS = "manage_providers"
    MANAGE_INTEGRATIONS = "manage_integrations"
    MANAGE_SCANS = "manage_scans"
    UNLIMITED_VISIBILITY = "unlimited_visibility"


# =============================================================================
# 2. get_role() - Returns FIRST role only (not aggregate)
# =============================================================================


def get_role(user: User) -> Optional[Role]:
    """
    Retrieve the first role assigned to the given user.

    IMPORTANT: This returns the FIRST role only via user.roles.first().
    There is NO aggregation of permissions across multiple roles.

    Returns:
        The user's first Role instance if any, otherwise None.
    """
    return user.roles.first()


# =============================================================================
# 3. get_providers() - Providers accessible via role's provider_groups
# =============================================================================


def get_providers(role: Role) -> QuerySet[Provider]:
    """
    Return providers accessible by the given role.

    Used when role does NOT have unlimited_visibility.
    Queries providers through the role's provider_groups.

    Args:
        role: A Role instance with provider_groups relationship.

    Returns:
        QuerySet[Provider] filtered by role's provider_groups.
        Returns empty queryset if role has no provider_groups.
    """
    tenant_id = role.tenant_id
    provider_groups = role.provider_groups.all()

    if not provider_groups.exists():
        return Provider.objects.none()

    return Provider.objects.filter(
        tenant_id=tenant_id, provider_groups__in=provider_groups
    ).distinct()


# =============================================================================
# 4. HasPermissions - DRF Permission Class
# =============================================================================


class HasPermissions(BasePermission):
    """
    DRF permission class checking required_permissions on ViewSet.

    Checks user's FIRST role (via roles.all()[0]) for each permission.
    Uses admin_db to bypass RLS for permission check.

    Usage:
        class MyViewSet(BaseRLSViewSet):
            required_permissions = [Permissions.MANAGE_PROVIDERS]
    """

    def has_permission(self, request, view):
        required_permissions = getattr(view, "required_permissions", [])
        if not required_permissions:
            return True

        # Query via admin_db to bypass RLS
        user_roles = (
            User.objects.using(MainRouter.admin_db).get(id=request.user.id).roles.all()
        )
        if not user_roles:
            return False

        # Check first role only for all permissions
        for perm in required_permissions:
            if not getattr(user_roles[0], perm.value, False):
                return False

        return True


# =============================================================================
# 5. ViewSet RBAC Pattern - Provider visibility filtering
# =============================================================================


class ProviderViewSet(BaseRLSViewSet):
    """
    Example ViewSet with RBAC visibility filtering.

    Pattern:
    1. Call get_role(user) to get user's first role
    2. Check role.unlimited_visibility
    3. If True: return all providers in tenant
    4. If False: return only providers from get_providers(role)
    """

    queryset = Provider.objects.all()
    serializer_class = ProviderSerializer
    filterset_class = ProviderFilter

    # Required for write operations (POST, PATCH, DELETE)
    required_permissions = [Permissions.MANAGE_PROVIDERS]

    def set_required_permissions(self):
        """Dynamic permission based on action (called before permission check)."""
        if self.action in ("list", "retrieve"):
            self.required_permissions = []
        else:
            self.required_permissions = [Permissions.MANAGE_PROVIDERS]

    def get_queryset(self):
        user_roles = get_role(self.request.user)

        if user_roles.unlimited_visibility:
            # Admin: sees all providers in tenant
            queryset = Provider.objects.filter(tenant_id=self.request.tenant_id)
        else:
            # Limited: filter by provider groups from role
            queryset = get_providers(user_roles)

        return queryset.select_related("secret").prefetch_related("provider_groups")


# =============================================================================
# 6. Finding/Resource ViewSet - Filter by provider visibility
# =============================================================================


class FindingViewSet(BaseRLSViewSet):
    """
    Findings filtered by user's provider visibility.

    Uses scan__provider__in for filtering when user lacks unlimited_visibility.
    Always uses all_objects manager (not filtered by provider deletion).
    """

    required_permissions = []  # Read-only, no required permissions

    def get_queryset(self):
        tenant_id = self.request.tenant_id
        user_roles = get_role(self.request.user)

        if user_roles.unlimited_visibility:
            queryset = Finding.all_objects.filter(tenant_id=tenant_id)
        else:
            # Filter by providers accessible through role's provider_groups
            queryset = Finding.all_objects.filter(
                scan__provider__in=get_providers(user_roles)
            )

        return queryset


class ResourceViewSet(BaseRLSViewSet):
    """
    Resources filtered by user's provider visibility.

    Uses provider__in for filtering when user lacks unlimited_visibility.
    """

    required_permissions = []

    def get_queryset(self):
        user_roles = get_role(self.request.user)

        if user_roles.unlimited_visibility:
            queryset = Resource.all_objects.filter(tenant_id=self.request.tenant_id)
        else:
            queryset = Resource.all_objects.filter(
                tenant_id=self.request.tenant_id, provider__in=get_providers(user_roles)
            )

        return queryset


# =============================================================================
# 7. Role Model - Permission flags and provider_groups
# =============================================================================


class Role(RowLevelSecurityProtectedModel):
    """
    Role defines permissions and provider group access.

    Permission flags are boolean columns (not M2M).
    Provider groups define visibility when unlimited_visibility=False.
    """

    name = models.CharField(max_length=255)

    # Permission flags (boolean columns)
    manage_users = models.BooleanField(default=False)
    manage_account = models.BooleanField(default=False)
    manage_billing = models.BooleanField(default=False)
    manage_providers = models.BooleanField(default=False)
    manage_integrations = models.BooleanField(default=False)
    manage_scans = models.BooleanField(default=False)
    unlimited_visibility = models.BooleanField(default=False)

    # Provider groups this role can access (when not unlimited_visibility)
    provider_groups = models.ManyToManyField(
        ProviderGroup,
        through="RoleProviderGroupRelationship",
        related_name="roles",
    )

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "roles"
        constraints = [
            models.UniqueConstraint(
                fields=["tenant_id", "name"],
                name="unique_role_name_per_tenant",
            ),
        ]


class UserRoleRelationship(RowLevelSecurityProtectedModel):
    """Associates users with roles within a tenant."""

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "role_user_relationship"


class RoleProviderGroupRelationship(RowLevelSecurityProtectedModel):
    """Associates roles with provider groups for visibility."""

    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    provider_group = models.ForeignKey(ProviderGroup, on_delete=models.CASCADE)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "role_provider_group_relationship"
