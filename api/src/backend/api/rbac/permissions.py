from enum import Enum
from typing import Optional

from django.db.models import QuerySet
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

        user_roles = (
            User.objects.using(MainRouter.admin_read)
            .get(id=request.user.id)
            .roles.all()
        )
        if not user_roles:
            return False

        for perm in required_permissions:
            if not getattr(user_roles[0], perm.value, False):
                return False

        return True


def get_role(user: User) -> Optional[Role]:
    """
    Retrieve the first role assigned to the given user.

    Returns:
        The user's first Role instance if the user has any roles, otherwise None.
    """
    return user.roles.first()


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
    tenant = role.tenant
    provider_groups = role.provider_groups.all()
    if not provider_groups.exists():
        return Provider.objects.none()

    return Provider.objects.filter(
        tenant=tenant, provider_groups__in=provider_groups
    ).distinct()
