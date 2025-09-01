from enum import Enum
from typing import Optional

from django.db.models import QuerySet
from rest_framework.permissions import BasePermission

from api.db_router import MainRouter
from api.models import Provider, Role, User, APIKeyUser


class Permissions(Enum):
    MANAGE_USERS = "manage_users"
    MANAGE_ACCOUNT = "manage_account"
    MANAGE_BILLING = "manage_billing"
    MANAGE_PROVIDERS = "manage_providers"
    MANAGE_INTEGRATIONS = "manage_integrations"
    MANAGE_SCANS = "manage_scans"
    UNLIMITED_VISIBILITY = "unlimited_visibility"


class IsAuthenticated(BasePermission):
    """
    Custom IsAuthenticated permission that handles both JWT and API key authentication.

    Allows access if:
    - User is authenticated (JWT authentication), OR
    - Request has valid API key authentication info
    """

    def has_permission(self, request, view):
        # Handle regular authenticated users (JWT)
        if request.user and request.user.is_authenticated:
            return True

        # Handle API key authentication (returns APIKeyUser)
        if isinstance(request.user, APIKeyUser):
            return True

        return False


class HasPermissions(BasePermission):
    """
    Custom permission to check if the user's role has the required permissions.
    The required permissions should be specified in the view as a list in `required_permissions`.
    """

    def has_permission(self, request, view):
        required_permissions = getattr(view, "required_permissions", [])
        if not required_permissions:
            return True

        # Handle API key authentication
        if isinstance(request.user, APIKeyUser):
            # Check API key's role permissions instead of granting unlimited access
            if not request.user.role:
                return False

            for perm in required_permissions:
                if not getattr(request.user.role, perm.value, False):
                    return False

            return True

        # Handle regular user authentication
        try:
            user_roles = (
                User.objects.using(MainRouter.admin_db)
                .get(id=request.user.id)
                .roles.all()
            )
            if not user_roles:
                return False

            for perm in required_permissions:
                if not getattr(user_roles[0], perm.value, False):
                    return False

            return True
        except User.DoesNotExist:
            return False


def get_role(user: User, request=None) -> Optional[Role]:
    """
    Retrieve the first role assigned to the given user.

    For API key authentication, returns the role associated with the API key.

    Returns:
        The user's first Role instance if the user has any roles,
        or the API key's role for API key authentication,
        otherwise None.
    """
    # Handle API key authentication
    if isinstance(user, APIKeyUser):
        # Return the actual role associated with the API key
        return user.role

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
