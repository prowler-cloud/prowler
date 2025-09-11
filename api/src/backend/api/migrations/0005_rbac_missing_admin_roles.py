from django.db import migrations

from api.db_router import MainRouter


def create_admin_role(apps, schema_editor):
    Tenant = apps.get_model("api", "Tenant")
    Role = apps.get_model("api", "Role")
    User = apps.get_model("api", "User")
    UserRoleRelationship = apps.get_model("api", "UserRoleRelationship")

    for tenant in Tenant.objects.using(MainRouter.admin_db).all():
        admin_role, _ = Role.objects.using(MainRouter.admin_db).get_or_create(
            name="admin",
            tenant=tenant,
            defaults={
                "manage_users": True,
                "manage_account": True,
                "manage_billing": True,
                "manage_providers": True,
                "manage_integrations": True,
                "manage_scans": True,
                "unlimited_visibility": True,
            },
        )
        users = User.objects.using(MainRouter.admin_db).filter(
            membership__tenant=tenant
        )
        for user in users:
            UserRoleRelationship.objects.using(MainRouter.admin_db).get_or_create(
                user=user,
                role=admin_role,
                tenant=tenant,
            )


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0004_rbac"),
    ]

    operations = [
        migrations.RunPython(create_admin_role),
    ]
