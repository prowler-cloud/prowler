from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.db import transaction

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
        if email:
            existing_user = self.get_user_by_email(email)
            if existing_user:
                sociallogin.connect(request, existing_user)

    def save_user(self, request, sociallogin, form=None):
        """
        Called after the user data is fully populated from the provider
        and is about to be saved to the DB for the first time.
        """
        with transaction.atomic():
            # Let allauth create/save the user
            user = super().save_user(request, sociallogin, form)
            # Handle all the extra logic required for new users in the application
            tenant = Tenant.objects.create(
                name=f"{user.email.split('@')[0]} default tenant"
            )
            with rls_transaction(str(tenant.id)):
                Membership.objects.create(
                    user=user, tenant=tenant, role=Membership.RoleChoices.OWNER
                )
                role = Role.objects.create(
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
                UserRoleRelationship.objects.create(
                    user=user,
                    role=role,
                    tenant_id=tenant.id,
                )
        return user
