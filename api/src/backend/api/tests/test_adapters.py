from unittest.mock import MagicMock

import pytest
from allauth.socialaccount.models import SocialLogin
from django.contrib.auth import get_user_model

from api.adapters import ProwlerSocialAccountAdapter
from api.db_router import MainRouter
from api.models import Membership, SAMLConfiguration, Tenant

User = get_user_model()


@pytest.mark.django_db
class TestProwlerSocialAccountAdapter:
    def test_get_user_by_email_returns_user(self, create_test_user):
        adapter = ProwlerSocialAccountAdapter()
        user = adapter.get_user_by_email(create_test_user.email)
        assert user == create_test_user

    def test_get_user_by_email_returns_none_for_unknown_email(self):
        adapter = ProwlerSocialAccountAdapter()
        assert adapter.get_user_by_email("notfound@example.com") is None

    def test_pre_social_login_links_existing_user(self, create_test_user, rf):
        adapter = ProwlerSocialAccountAdapter()

        sociallogin = MagicMock(spec=SocialLogin)
        sociallogin.account = MagicMock()
        sociallogin.account.provider = "saml"
        sociallogin.account.extra_data = {}
        sociallogin.user = create_test_user
        sociallogin.connect = MagicMock()

        adapter.pre_social_login(rf.get("/"), sociallogin)

        call_args = sociallogin.connect.call_args
        assert call_args is not None

        called_request, called_user = call_args[0]
        assert called_request.path == "/"
        assert called_user.email == create_test_user.email

    def test_pre_social_login_no_link_if_email_missing(self, rf):
        adapter = ProwlerSocialAccountAdapter()

        sociallogin = MagicMock(spec=SocialLogin)
        sociallogin.account = MagicMock()
        sociallogin.account.provider = "github"
        sociallogin.account.extra_data = {}
        sociallogin.connect = MagicMock()

        adapter.pre_social_login(rf.get("/"), sociallogin)

        sociallogin.connect.assert_not_called()

    def test_save_user_saml_flow(
        self,
        rf,
        saml_setup,
        saml_sociallogin,
    ):
        adapter = ProwlerSocialAccountAdapter()
        request = rf.get("/")
        saml_sociallogin.user.email = saml_setup["email"]
        saml_sociallogin.account.extra_data = {
            "firstName": [],
            "lastName": [],
            "organization": [],
            "userType": [],
        }

        tenant = Tenant.objects.using(MainRouter.admin_db).get(
            id=saml_setup["tenant_id"]
        )
        saml_config = SAMLConfiguration.objects.using(MainRouter.admin_db).get(
            tenant=tenant
        )
        assert saml_config.email_domain == saml_setup["domain"]

        user = adapter.save_user(request, saml_sociallogin)

        assert user.name == "N/A"
        assert user.company_name == ""
        assert user.email == saml_setup["email"]
        assert (
            Membership.objects.using(MainRouter.admin_db)
            .filter(user=user, tenant=tenant)
            .exists()
        )
