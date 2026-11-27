from unittest import mock

import requests

from prowler.providers.supabase.services.auth import auth_service
from tests.providers.supabase.supabase_fixtures import (
    ORGANIZATION_SLUG,
    PROJECT_NAME,
    PROJECT_REF,
    set_mocked_supabase_provider,
)


def _response(status_code=200, payload=None):
    response = mock.MagicMock(status_code=status_code, headers={})
    response.json.return_value = payload
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(
            f"{status_code} error"
        )
    return response


class TestAuthService:
    def test_keeps_only_non_secret_settings(self):
        provider = set_mocked_supabase_provider()
        routes = {
            "/v1/projects": _response(
                payload=[
                    {
                        "ref": PROJECT_REF,
                        "name": PROJECT_NAME,
                        "organization_slug": ORGANIZATION_SLUG,
                    }
                ]
            ),
            f"/v1/projects/{PROJECT_REF}/config/auth": _response(
                payload={
                    "disable_signup": False,
                    "external_anonymous_users_enabled": True,
                    "mailer_autoconfirm": False,
                    "mailer_otp_exp": 86400,
                    "password_min_length": 6,
                    "password_hibp_enabled": False,
                    "mfa_totp_enroll_enabled": False,
                    "mfa_phone_enroll_enabled": False,
                    "mfa_web_authn_enroll_enabled": True,
                    "refresh_token_rotation_enabled": True,
                    "security_captcha_enabled": False,
                    "security_captcha_secret": "do-not-store",
                    "smtp_pass": "do-not-store",
                    "external_github_secret": "do-not-store",
                }
            ),
        }
        provider.session.http_session.get.side_effect = lambda url, timeout=30: routes[
            url.replace("https://api.supabase.com", "")
        ]

        service = auth_service.Auth(provider)

        config = service.configs[PROJECT_REF]
        assert config.external_anonymous_users_enabled is True
        assert config.mailer_otp_exp == 86400
        assert config.password_min_length == 6
        assert config.mfa_enrollment_enabled is True
        dumped = str(config.model_dump())
        assert "do-not-store" not in dumped

    def test_project_without_auth_config_is_skipped(self):
        provider = set_mocked_supabase_provider()
        routes = {
            "/v1/projects": _response(
                payload=[
                    {
                        "ref": PROJECT_REF,
                        "name": PROJECT_NAME,
                        "organization_slug": ORGANIZATION_SLUG,
                    }
                ]
            ),
            f"/v1/projects/{PROJECT_REF}/config/auth": _response(
                status_code=404, payload={}
            ),
        }
        provider.session.http_session.get.side_effect = lambda url, timeout=30: routes[
            url.replace("https://api.supabase.com", "")
        ]

        with mock.patch("prowler.providers.supabase.lib.service.service.time.sleep"):
            service = auth_service.Auth(provider)

        assert service.configs == {}
