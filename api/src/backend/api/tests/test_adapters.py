from unittest.mock import MagicMock, patch

import pytest
from allauth.socialaccount.models import SocialLogin
from django.contrib.auth import get_user_model

from api.adapters import ProwlerSocialAccountAdapter

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
        sociallogin.provider = MagicMock()
        sociallogin.provider.id = "saml"
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
        sociallogin.provider = MagicMock()
        sociallogin.user = MagicMock()
        sociallogin.provider.id = "saml"
        sociallogin.account.extra_data = {}
        sociallogin.connect = MagicMock()

        adapter.pre_social_login(rf.get("/"), sociallogin)

        sociallogin.connect.assert_not_called()

    def test_save_user_saml_sets_session_flag(self, rf):
        adapter = ProwlerSocialAccountAdapter()
        request = rf.get("/")
        request.session = {}

        sociallogin = MagicMock(spec=SocialLogin)
        sociallogin.provider = MagicMock()
        sociallogin.provider.id = "saml"
        sociallogin.account = MagicMock()
        sociallogin.account.extra_data = {}

        mock_user = MagicMock()
        mock_user.id = 123

        with patch("api.adapters.super") as mock_super:
            with patch("api.adapters.transaction"):
                with patch("api.adapters.MainRouter"):
                    mock_super.return_value.save_user.return_value = mock_user
                    adapter.save_user(request, sociallogin)
                    assert request.session["saml_user_created"] == "123"
