from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import Membership, Role, Tenant, User, UserRoleRelationship


def provision_default_tenant_access(user: User) -> Tenant:
    tenant = Tenant.objects.using(MainRouter.admin_db).create(
        name=f"{user.email.split('@')[0]} default tenant"
    )

    with rls_transaction(str(tenant.id), using=MainRouter.admin_db):
        Membership.objects.using(MainRouter.admin_db).create(
            user=user,
            tenant=tenant,
            role=Membership.RoleChoices.OWNER,
        )
        role = Role.objects.using(MainRouter.admin_db).create(
            name="admin",
            tenant_id=tenant.id,
            manage_users=True,
            manage_account=True,
            manage_billing=True,
            manage_providers=True,
            manage_integrations=True,
            manage_scans=True,
            unlimited_visibility=True,
        )
        UserRoleRelationship.objects.using(MainRouter.admin_db).create(
            user=user,
            role=role,
            tenant_id=tenant.id,
        )

    return tenant