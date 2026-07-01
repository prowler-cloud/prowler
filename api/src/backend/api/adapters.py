from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
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
from api.utils import accept_invitation_for_user
from django.db import transaction


class ProwlerSocialAccountAdapter(DefaultSocialAccountAdapter):
    @staticmethod
    def get_user_by_email(email: str):
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None

    @staticmethod
    def _get_invitation_token(request):
        for source_name in ("data", "POST"):
            data = getattr(request, source_name, None) or {}
            if not hasattr(data, "get"):
                continue
            invitation_token = data.get("invitation_token")
            if invitation_token:
                return invitation_token

        wrapped_request = getattr(request, "_request", None)
        if wrapped_request and wrapped_request is not request:
            return ProwlerSocialAccountAdapter._get_invitation_token(wrapped_request)

        return None

    def pre_social_login(self, request, sociallogin):
        # Link existing accounts with the same email address
        email = sociallogin.account.extra_data.get("email")
        if sociallogin.provider.id == "saml":
            # For SAML, the asserted NameID email cannot be trusted on its own:
            # any tenant can claim any email domain in its SAML configuration. To
            # prevent cross-tenant account takeover (GHSA-h8m9-jgf8-vwvp), only link
            # the incoming SAML session to an existing account when (1) the email
            # domain matches the tenant whose ACS endpoint is being used and (2) the
            # existing user is already a member of that tenant.
            email = sociallogin.user.email
            if not email:
                return

            domain = email.rsplit("@", 1)[-1].lower()
            resolver_match = getattr(request, "resolver_match", None)
            organization_slug = (
                (resolver_match.kwargs or {}).get("organization_slug", "")
                if resolver_match
                else ""
            ).lower()
            # The ACS endpoint is scoped per email domain; reject mismatches so an
            # attacker cannot replay an assertion through another tenant's endpoint.
            if organization_slug != domain:
                return

            try:
                saml_config = SAMLConfiguration.objects.using(MainRouter.admin_db).get(
                    email_domain=domain
                )
            except SAMLConfiguration.DoesNotExist:
                return

            existing_user = self.get_user_by_email(email)
            if existing_user and existing_user.is_member_of_tenant(
                str(saml_config.tenant_id)
            ):
                sociallogin.connect(request, existing_user)
            return

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

                invitation_token = self._get_invitation_token(request)
                if invitation_token:
                    invitation, _ = accept_invitation_for_user(
                        user=user,
                        invitation_token=invitation_token,
                    )
                    request.prowler_invitation_token = invitation_token
                    request.prowler_invitation_tenant_id = str(invitation.tenant_id)
                else:
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
            else:
                request.session["saml_user_created"] = str(user.id)

        return user
