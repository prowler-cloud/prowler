from unittest.mock import patch
from urllib.parse import urlencode

import pytest
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

GITHUB_ADAPTER = (
    "allauth.socialaccount.providers.github.views.GitHubOAuth2Adapter.complete_login"
)


def post_form(url_name, payload):
    # The UI posts the OAuth callback params as a form, not JSON:API.
    return APIClient().post(
        reverse(url_name),
        data=urlencode(payload),
        content_type="application/x-www-form-urlencoded",
    )


GOOGLE_ADAPTER = (
    "allauth.socialaccount.providers.google.views.GoogleOAuth2Adapter.complete_login"
)


@pytest.mark.django_db
class TestSocialLoginTokenSubstitution:
    """Social login must only trust tokens obtained by exchanging a code.

    A caller-supplied access_token (or id_token) may have been issued to any
    OAuth client, so accepting it allows account takeover.
    """

    @pytest.mark.parametrize(
        "url_name, adapter_path, payload",
        [
            ("token-github", GITHUB_ADAPTER, {"access_token": "gho_victim"}),
            ("token-google", GOOGLE_ADAPTER, {"access_token": "ya29.victim"}),
            ("token-google", GOOGLE_ADAPTER, {"id_token": "eyJ.victim.token"}),
            (
                "token-google",
                GOOGLE_ADAPTER,
                {"access_token": "ya29.victim", "id_token": "eyJ.victim.token"},
            ),
            (
                "token-github",
                GITHUB_ADAPTER,
                {"access_token": "gho_victim", "code": "auth-code"},
            ),
        ],
    )
    def test_rejects_caller_supplied_tokens(self, url_name, adapter_path, payload):
        with patch(adapter_path) as mocked_complete_login:
            response = post_form(url_name, payload)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        mocked_complete_login.assert_not_called()

    @pytest.mark.parametrize("url_name", ["token-github", "token-google"])
    def test_requires_authorization_code(self, url_name):
        response = post_form(url_name, {})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "url_name, view_path",
        [
            ("token-github", "api.v1.views.GithubSocialLoginView"),
            ("token-google", "api.v1.views.GoogleSocialLoginView"),
        ],
    )
    def test_authorization_code_is_exchanged_server_side(self, url_name, view_path):
        with (
            patch(f"{view_path}.callback_url", "https://app.example.com/callback"),
            patch(
                "api.utils.CustomOAuth2Client.get_access_token",
                side_effect=OAuth2Error("invalid code"),
            ) as mocked_exchange,
        ):
            response = post_form(url_name, {"code": "auth-code"})

        mocked_exchange.assert_called_once_with("auth-code")
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "url_name, response_type",
        [
            ("token-github", "github-social-tokens"),
            ("token-google", "google-social-tokens"),
        ],
    )
    def test_authorization_code_login_returns_prowler_tokens(
        self, create_test_user_rbac, url_name, response_type
    ):
        received_attrs = {}

        def successful_exchange(serializer, attrs):
            # Stands in for the provider round trip: code exchange + profile.
            received_attrs.update(attrs)
            return {**attrs, "user": create_test_user_rbac}

        with patch(
            "dj_rest_auth.registration.serializers.SocialLoginSerializer.validate",
            autospec=True,
            side_effect=successful_exchange,
        ):
            response = post_form(url_name, {"code": "auth-code"})

        assert response.status_code == status.HTTP_200_OK
        assert received_attrs["code"] == "auth-code"
        data = response.json()["data"]
        assert data["type"] == response_type
        assert data["attributes"]["access"]
        assert data["attributes"]["refresh"]
