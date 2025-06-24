from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.db import transaction

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import (
    Membership,
    Role,
    SAMLConfiguration,
    Tenant,
    User,
    UserRoleRelationship,
)


class ProwlerSocialAccountAdapter(DefaultSocialAccountAdapter):
    @staticmethod
    def get_user_by_email(email: str):
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None

    def pre_social_login(self, request, sociallogin):
        # Link existing accounts with the same email address
        email = sociallogin.account.extra_data.get("email")
        if sociallogin.account.provider == "saml":
            email = sociallogin.user.email
        if email:
            existing_user = self.get_user_by_email(email)
            if existing_user:
                sociallogin.connect(request, existing_user)

    def save_user(self, request, sociallogin, form=None):
        """
        Called after the user data is fully populated from the provider
        and is about to be saved to the DB for the first time.
        """
        with transaction.atomic(using=MainRouter.admin_db):
            user = super().save_user(request, sociallogin, form)
            provider = sociallogin.account.provider
            extra = sociallogin.account.extra_data

            if provider == "saml":
                # Handle SAML-specific logic
                user.first_name = (
                    extra.get("firstName", [""])[0] if extra.get("firstName") else ""
                )
                user.last_name = (
                    extra.get("lastName", [""])[0] if extra.get("lastName") else ""
                )
                user.company_name = (
                    extra.get("organization", [""])[0]
                    if extra.get("organization")
                    else ""
                )
                user.name = f"{user.first_name} {user.last_name}".strip()
                if user.name == "":
                    user.name = "N/A"
                user.save(using=MainRouter.admin_db)

                email_domain = user.email.split("@")[-1]
                tenant = (
                    SAMLConfiguration.objects.using(MainRouter.admin_db)
                    .get(email_domain=email_domain)
                    .tenant
                )

                with rls_transaction(str(tenant.id)):
                    role_name = (
                        extra.get("userType", ["saml_default_role"])[0].strip()
                        if extra.get("userType")
                        else "saml_default_role"
                    )

                    try:
                        role = Role.objects.using(MainRouter.admin_db).get(
                            name=role_name, tenant_id=tenant.id
                        )
                    except Role.DoesNotExist:
                        role = Role.objects.using(MainRouter.admin_db).create(
                            name=role_name,
                            tenant_id=tenant.id,
                            manage_users=False,
                            manage_account=False,
                            manage_billing=False,
                            manage_providers=False,
                            manage_integrations=False,
                            manage_scans=False,
                            unlimited_visibility=False,
                        )

                    Membership.objects.using(MainRouter.admin_db).create(
                        user=user,
                        tenant=tenant,
                        role=Membership.RoleChoices.MEMBER,
                    )

                    UserRoleRelationship.objects.using(MainRouter.admin_db).create(
                        user=user,
                        role=role,
                        tenant_id=tenant.id,
                    )

            else:
                # Handle other providers (e.g., GitHub, Google)
                user.save(using=MainRouter.admin_db)
                social_account_name = extra.get("name")
                if social_account_name:
                    user.name = social_account_name
                    user.save(using=MainRouter.admin_db)

                tenant = Tenant.objects.using(MainRouter.admin_db).create(
                    name=f"{user.email.split('@')[0]} default tenant"
                )
                with rls_transaction(str(tenant.id)):
                    Membership.objects.using(MainRouter.admin_db).create(
                        user=user, tenant=tenant, role=Membership.RoleChoices.OWNER
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

        return user
