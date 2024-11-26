from config.django.base import DISABLE_RBAC

from enum import Enum
from rest_framework.permissions import BasePermission


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
        # This is for testing/demo purposes only
        if DISABLE_RBAC:
            return True

        required_permissions = getattr(view, "required_permissions", [])
        if not required_permissions:
            return True

        user_roles = request.user.roles.all()
        if not user_roles:
            return False

        for perm in required_permissions:
            if not getattr(user_roles[0], perm.value, False):
                return False

        return True
