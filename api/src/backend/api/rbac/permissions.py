from enum import Enum

from api.db_router import MainRouter
from api.models import Integration, Provider, Role, Task, User
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


# Revoking a task needs the permission of the operation that queued it.
# None and unmapped names are not revocable; a revoked provider deletion
# would leave the provider soft-deleted with nothing re-queuing the cleanup.
TASK_REVOKE_PERMISSIONS: dict[str, list[Permissions] | None] = {
    "provider-connection-check": [Permissions.MANAGE_PROVIDERS],
    "provider-deletion": None,
    "integration-connection-check": [Permissions.MANAGE_INTEGRATIONS],
    "integration-s3": [Permissions.MANAGE_INTEGRATIONS],
    "integration-security-hub": [Permissions.MANAGE_INTEGRATIONS],
    "integration-jira": [Permissions.MANAGE_INTEGRATIONS],
    "scan-perform": [Permissions.MANAGE_SCANS],
    "scan-perform-scheduled": [Permissions.MANAGE_SCANS],
    "scan-compliance-overviews": [Permissions.MANAGE_SCANS],
    "scan-compliance-reports": [Permissions.MANAGE_SCANS],
    "scan-finding-group-summaries": [Permissions.MANAGE_SCANS],
    "scan-report": [Permissions.MANAGE_SCANS],
    "attack-paths-scan-perform": [Permissions.MANAGE_SCANS],
    "findings-mute-latest-scans": [Permissions.MANAGE_SCANS],
    "lighthouse-connection-check": [],
    "lighthouse-provider-connection-check": [],
    "lighthouse-provider-models-refresh": [],
}


def get_user_roles(user: User, tenant_id: str) -> list[Role]:
    """Return every role assigned to the user in the tenant."""
    return list(
        User.objects.using(MainRouter.admin_db)
        .get(id=user.id)
        .roles.using(MainRouter.admin_db)
        .filter(tenant_id=tenant_id)
    )


def roles_have_permissions(
    roles: list[Role], required_permissions: list[Permissions]
) -> bool:
    """Return True when every required permission is granted by at least one role."""
    return all(
        any(getattr(role, permission.value, False) for role in roles)
        for permission in required_permissions
    )


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

        user_roles = get_user_roles(request.user, tenant_id)
        if not user_roles:
            return False

        return roles_have_permissions(user_roles, required_permissions)


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


def get_tasks(role: Role) -> QuerySet[Task]:
    """Return the tasks visible to the role: tenant-wide ones and those of its providers."""
    queryset = Task.objects.filter(tenant_id=role.tenant_id)
    if role.unlimited_visibility:
        return queryset

    # Task has no provider FK, so match provider ids inside the stored kwargs.
    # all_objects keeps a soft-deleted provider visible to its own groups, so the
    # role that queued its deletion can still follow the task.
    hidden = Q()
    for provider_id in (
        Provider.all_objects.filter(tenant_id=role.tenant_id)
        .exclude(provider_groups__in=role.provider_groups.all())
        .values_list("id", flat=True)
    ):
        hidden |= Q(task_runner_task__task_kwargs__contains=str(provider_id))
    return queryset.exclude(hidden) if hidden else queryset


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
