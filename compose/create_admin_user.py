import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.production")
django.setup()

from api.models import User, Membership, Role, UserRoleRelationship
from api.rls import Tenant
from api.db_router import MainRouter

email = os.environ.get("DJANGO_SUPERUSER_EMAIL")
password = os.environ.get("DJANGO_SUPERUSER_PASSWORD")
name = os.environ.get("DJANGO_SUPERUSER_NAME", "Admin")
tenant_name = "Prowler Admin Tenant"

if not email or not password:
    print("DJANGO_SUPERUSER_EMAIL and DJANGO_SUPERUSER_PASSWORD must be set.")
    exit(1)

# Create Tenant
tenants = Tenant.objects.using(MainRouter.admin_db).filter(name=tenant_name)
if tenants.count() > 1:
    print(f"Found {tenants.count()} tenants with name '{tenant_name}'. Cleaning up duplicates...")
    tenant = tenants.first()
    # Delete others
    Tenant.objects.using(MainRouter.admin_db).filter(name=tenant_name).exclude(pk=tenant.pk).delete()
    created = False
    print(f"Kept tenant '{tenant_name}' (ID: {tenant.id}) and deleted duplicates.")
else:
    tenant, created = Tenant.objects.using(MainRouter.admin_db).get_or_create(name=tenant_name)
    if created:
        print(f"Tenant '{tenant_name}' created.")
    else:
        print(f"Tenant '{tenant_name}' already exists.")

# Create User
user, created = User.objects.using(MainRouter.admin_db).get_or_create(email=email, defaults={'name': name})
if created:
    user.set_password(password)
    user.save(using=MainRouter.admin_db)
    print(f"User {email} created.")
else:
    print(f"User {email} already exists.")

# Create Membership
membership, created = Membership.objects.using(MainRouter.admin_db).get_or_create(
    user=user,
    tenant=tenant,
    defaults={'role': Membership.RoleChoices.OWNER}
)

if created:
    print(f"User {email} added as OWNER to tenant '{tenant_name}'.")
else:
    if membership.role != Membership.RoleChoices.OWNER:
        membership.role = Membership.RoleChoices.OWNER
        membership.save(using=MainRouter.admin_db)
        print(f"User {email} role updated to OWNER in tenant '{tenant_name}'.")
    else:
        print(f"User {email} is already OWNER of tenant '{tenant_name}'.")

# Create Admin Role
role, created = Role.objects.using(MainRouter.admin_db).get_or_create(
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
    }
)

if created:
    print(f"Role 'admin' created for tenant '{tenant_name}'.")
else:
    print(f"Role 'admin' already exists for tenant '{tenant_name}'.")

# Assign Role to User
user_role, created = UserRoleRelationship.objects.using(MainRouter.admin_db).get_or_create(
    user=user,
    role=role,
    tenant=tenant
)

if created:
    print(f"User {email} assigned 'admin' role in tenant '{tenant_name}'.")
else:
    print(f"User {email} already has 'admin' role in tenant '{tenant_name}'.")

print(f"Tenant ID: {tenant.id}")
