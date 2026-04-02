from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import Membership, Role, Tenant, User, UserRoleRelationship


ROLE_PRESETS = {
    "admin": {
        "membership_role": Membership.RoleChoices.OWNER,
        "role_name": "admin",
        "manage_users": True,
        "manage_account": True,
        "manage_billing": True,
        "manage_providers": True,
        "manage_integrations": True,
        "manage_scans": True,
        "unlimited_visibility": True,
    },
    "editor": {
        "membership_role": Membership.RoleChoices.MEMBER,
        "role_name": "editor",
        "manage_users": False,
        "manage_account": False,
        "manage_billing": False,
        "manage_providers": True,
        "manage_integrations": True,
        "manage_scans": True,
        "unlimited_visibility": True,
    },
    "read": {
        "membership_role": Membership.RoleChoices.MEMBER,
        "role_name": "read",
        "manage_users": False,
        "manage_account": False,
        "manage_billing": False,
        "manage_providers": False,
        "manage_integrations": False,
        "manage_scans": False,
        "unlimited_visibility": True,
    },
}


def get_default_tenant_role_preset(role_name: str):
    normalized_role_name = (role_name or "admin").strip().lower()
    return ROLE_PRESETS.get(normalized_role_name, ROLE_PRESETS["admin"])


def provision_default_tenant_access(user: User, role_name: str = "admin") -> Tenant:
    role_preset = get_default_tenant_role_preset(role_name)
    tenant = Tenant.objects.using(MainRouter.admin_db).create(
        name=f"{user.email.split('@')[0]} default tenant"
    )

    with rls_transaction(str(tenant.id), using=MainRouter.admin_db):
        Membership.objects.using(MainRouter.admin_db).create(
            user=user,
            tenant=tenant,
            role=role_preset["membership_role"],
        )
        role = Role.objects.using(MainRouter.admin_db).create(
            name=role_preset["role_name"],
            tenant_id=tenant.id,
            manage_users=role_preset["manage_users"],
            manage_account=role_preset["manage_account"],
            manage_billing=role_preset["manage_billing"],
            manage_providers=role_preset["manage_providers"],
            manage_integrations=role_preset["manage_integrations"],
            manage_scans=role_preset["manage_scans"],
            unlimited_visibility=role_preset["unlimited_visibility"],
        )
        UserRoleRelationship.objects.using(MainRouter.admin_db).create(
            user=user,
            role=role,
            tenant_id=tenant.id,
        )

    return tenant