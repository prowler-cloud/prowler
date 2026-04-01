from enum import Enum

from django.db.models import QuerySet
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from api.db_router import MainRouter
from api.models import Provider, Role, User


class Permissions(Enum):
    MANAGE_USERS = "manage_users"
    MANAGE_ACCOUNT = "manage_account"
    MANAGE_BILLING = "manage_billing"
    MANAGE_PROVIDERS = "manage_providers"
    MANAGE_INTEGRATIONS = "manage_integrations"
    MANAGE_SCANS = "manage_scans"
    UNLIMITED_VISIBILITY = "unlimited_visibility"


class HasPermissions(BasePermission):
    """
    Custom permission to check if the user's role has the required permissions.
    The required permissions should be specified in the view as a list in `required_permissions`.
    """

    def has_permission(self, request, view):
        required_permissions = getattr(view, "required_permissions", [])
        if not required_permissions:
            return True

        tenant_id = getattr(request, "tenant_id", None)
        if not tenant_id:
            tenant_id = request.auth.get("tenant_id") if request.auth else None
        if not tenant_id:
            return False

        user_roles = (
            User.objects.using(MainRouter.admin_db)
            .get(id=request.user.id)
            .roles.using(MainRouter.admin_db)
            .filter(tenant_id=tenant_id)
        )
        if not user_roles:
            return False

        for perm in required_permissions:
            if not getattr(user_roles[0], perm.value, False):
                return False

        return True


def get_role(user: User, tenant_id: str) -> Role:
    """
    Retrieve the role assigned to the given user in the specified tenant.

    Raises:
        PermissionDenied: If the user has no role in the given tenant.
    """
    role = user.roles.using(MainRouter.admin_db).filter(tenant_id=tenant_id).first()
    if role is None:
        raise PermissionDenied("User has no role in this tenant.")
    return role


def get_providers(role: Role) -> QuerySet[Provider]:
    """
    Return a distinct queryset of Providers accessible by the given role.

    If the role has no associated provider groups, an empty queryset is returned.

    Args:
        role: A Role instance.

    Returns:
        A QuerySet of Provider objects filtered by the role's provider groups.
        If the role has no provider groups, returns an empty queryset.
    """
    tenant_id = role.tenant_id
    provider_groups = role.provider_groups.all()
    if not provider_groups.exists():
        return Provider.objects.none()

    return Provider.objects.filter(
        tenant_id=tenant_id, provider_groups__in=provider_groups
    ).distinct()
