from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.db import transaction

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import Membership, Role, Tenant, User, UserRoleRelationship


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
        if sociallogin.provider.id == "saml":
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
            provider = sociallogin.provider.id
            extra = sociallogin.account.extra_data

            if provider != "saml":
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
