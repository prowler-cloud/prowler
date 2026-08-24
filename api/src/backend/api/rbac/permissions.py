from enum import Enum

from api.db_router import MainRouter
from api.models import Integration, Provider, Role, User
from django.db.models import Q, QuerySet
from rest_framework.exceptions import PermissionDenied
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
        required_permissions = getattr(view, "required_permissions", [])
        if not required_permissions:
            return True

        tenant_id = getattr(request, "tenant_id", None)
        if not tenant_id:
            tenant_id = request.auth.get("tenant_id") if request.auth else None
        if not tenant_id:
            return False

        user_roles = list(
            User.objects.using(MainRouter.admin_db)
            .get(id=request.user.id)
            .roles.using(MainRouter.admin_db)
            .filter(tenant_id=tenant_id)
        )
        if not user_roles:
            return False

        return all(
            any(getattr(role, permission.value, False) for role in user_roles)
            for permission in required_permissions
        )


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


def get_integrations(
    role: Role, providers: QuerySet[Provider] | None = None
) -> QuerySet[Integration]:
    """
    Return a distinct queryset of Integrations visible to the given role.

    Integrations with no providers attached are tenant-wide, as is always the case for
    Jira, and stay visible regardless of the provider visibility of the role. Integrations
    attached to providers are only visible when the role can access at least one of them.

    Args:
        role: A Role instance.
        providers: Optional queryset of the providers accessible by the role, to reuse
            an already resolved `get_providers(role)` result within the same request.

    Returns:
        A QuerySet of Integration objects visible to the role.
    """
    queryset = Integration.objects.filter(tenant_id=role.tenant_id)
    if role.unlimited_visibility:
        return queryset

    if providers is None:
        providers = get_providers(role)
    return queryset.filter(
        Q(providers__isnull=True) | Q(providers__in=providers)
    ).distinct()
