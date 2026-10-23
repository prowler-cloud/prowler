from unittest import mock

from prowler.providers.supabase.services.projects.projects_service import (
    SupabaseProject,
)
from tests.providers.supabase.supabase_fixtures import (
    ORGANIZATION_NAME,
    ORGANIZATION_SLUG,
    PROJECT_NAME,
    PROJECT_REF,
    PROJECT_REGION,
    set_mocked_supabase_provider,
)

CHECK_PATH = "prowler.providers.supabase.services.projects.projects_legacy_api_keys_disabled.projects_legacy_api_keys_disabled"


def _project(**overrides):
    return SupabaseProject(
        id=PROJECT_REF,
        name=PROJECT_NAME,
        project_ref=PROJECT_REF,
        project_name=PROJECT_NAME,
        organization_slug=ORGANIZATION_SLUG,
        organization_name=ORGANIZATION_NAME,
        region=PROJECT_REGION,
        **overrides,
    )


def _run(projects_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_supabase_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.projects_client", new=projects_client),
    ):
        from prowler.providers.supabase.services.projects.projects_legacy_api_keys_disabled.projects_legacy_api_keys_disabled import (
            projects_legacy_api_keys_disabled,
        )

        return projects_legacy_api_keys_disabled().execute()


class Test_projects_legacy_api_keys_disabled:
    def test_no_projects(self):
        projects_client = mock.MagicMock
        projects_client.audit_config = {}
        projects_client.projects = {}

        assert len(_run(projects_client)) == 0

    def test_pass(self):
        projects_client = mock.MagicMock
        projects_client.audit_config = {}
        projects_client.projects = {
            PROJECT_REF: _project(**{"legacy_api_keys_enabled": False})
        }

        result = _run(projects_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Project {PROJECT_NAME} has the legacy anon and service_role API keys disabled."
        )
        assert result[0].resource_id == PROJECT_REF
        assert result[0].resource_name == PROJECT_NAME
        assert result[0].organization_slug == ORGANIZATION_SLUG
        assert result[0].region == PROJECT_REGION

    def test_fail(self):
        projects_client = mock.MagicMock
        projects_client.audit_config = {}
        projects_client.projects = {
            PROJECT_REF: _project(**{"legacy_api_keys_enabled": True})
        }

        result = _run(projects_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Project {PROJECT_NAME} still accepts the legacy anon and service_role JWT API keys."
        )

    def test_unknown_setting_is_skipped(self):
        projects_client = mock.MagicMock
        projects_client.audit_config = {}
        projects_client.projects = {
            PROJECT_REF: _project(**{"legacy_api_keys_enabled": None})
        }

        assert len(_run(projects_client)) == 0
