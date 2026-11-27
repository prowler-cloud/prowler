from unittest import mock

from prowler.providers.supabase.services.auth.auth_service import SupabaseAuthConfig
from tests.providers.supabase.supabase_fixtures import (
    ORGANIZATION_NAME,
    ORGANIZATION_SLUG,
    PROJECT_NAME,
    PROJECT_REF,
    PROJECT_REGION,
    set_mocked_supabase_provider,
)

CHECK_PATH = "prowler.providers.supabase.services.auth.auth_mfa_enrollment_enabled.auth_mfa_enrollment_enabled"


def _config(**overrides):
    return SupabaseAuthConfig(
        id=PROJECT_REF,
        name=PROJECT_NAME,
        project_ref=PROJECT_REF,
        project_name=PROJECT_NAME,
        organization_slug=ORGANIZATION_SLUG,
        organization_name=ORGANIZATION_NAME,
        region=PROJECT_REGION,
        **overrides,
    )


def _run(auth_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_supabase_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.auth_client", new=auth_client),
    ):
        from prowler.providers.supabase.services.auth.auth_mfa_enrollment_enabled.auth_mfa_enrollment_enabled import (
            auth_mfa_enrollment_enabled,
        )

        return auth_mfa_enrollment_enabled().execute()


class Test_auth_mfa_enrollment_enabled:
    def test_no_configs(self):
        auth_client = mock.MagicMock
        auth_client.audit_config = {}
        auth_client.configs = {}

        assert len(_run(auth_client)) == 0

    def test_pass(self):
        auth_client = mock.MagicMock
        auth_client.audit_config = {}
        auth_client.configs = {
            PROJECT_REF: _config(**{"mfa_totp_enroll_enabled": True})
        }

        result = _run(auth_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Project {PROJECT_NAME} lets users enroll multi-factor authentication."
        )
        assert result[0].resource_id == PROJECT_REF
        assert result[0].resource_name == PROJECT_NAME
        assert result[0].organization_slug == ORGANIZATION_SLUG
        assert result[0].region == PROJECT_REGION

    def test_fail(self):
        auth_client = mock.MagicMock
        auth_client.audit_config = {}
        auth_client.configs = {
            PROJECT_REF: _config(
                **{
                    "mfa_totp_enroll_enabled": False,
                    "mfa_phone_enroll_enabled": False,
                    "mfa_web_authn_enroll_enabled": False,
                }
            )
        }

        result = _run(auth_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Project {PROJECT_NAME} has every multi-factor enrollment method disabled."
        )

    def test_unknown_setting_is_skipped(self):
        auth_client = mock.MagicMock
        auth_client.audit_config = {}
        auth_client.configs = {
            PROJECT_REF: _config(**{"mfa_totp_enroll_enabled": None})
        }

        assert len(_run(auth_client)) == 0
