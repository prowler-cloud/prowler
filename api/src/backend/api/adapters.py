from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.db import transaction

from api.account_bootstrap import provision_default_tenant_access
from api.db_router import MainRouter
from api.models import User


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
                provision_default_tenant_access(user)
            else:
                request.session["saml_user_created"] = str(user.id)

        return user
