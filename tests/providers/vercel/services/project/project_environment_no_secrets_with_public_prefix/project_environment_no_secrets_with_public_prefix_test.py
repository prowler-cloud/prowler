from unittest import mock

from prowler.providers.vercel.services.project.project_service import (
    VercelEnvironmentVariable,
    VercelProject,
)
from tests.providers.vercel.vercel_fixtures import (
    PROJECT_ID,
    PROJECT_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)

CHECK_PATH = "prowler.providers.vercel.services.project.project_environment_no_secrets_with_public_prefix.project_environment_no_secrets_with_public_prefix"


def _project(env_vars):
    return VercelProject(
        id=PROJECT_ID,
        name=PROJECT_NAME,
        team_id=TEAM_ID,
        environment_variables=env_vars,
    )


def _env(key, type="encrypted"):
    return VercelEnvironmentVariable(
        id=f"env_{key.lower()}", key=key, type=type, project_id=PROJECT_ID
    )


def _run(project_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_vercel_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.project_client", new=project_client),
    ):
        from prowler.providers.vercel.services.project.project_environment_no_secrets_with_public_prefix.project_environment_no_secrets_with_public_prefix import (
            project_environment_no_secrets_with_public_prefix,
        )

        return project_environment_no_secrets_with_public_prefix().execute()


class Test_project_environment_no_secrets_with_public_prefix:
    def test_no_projects(self):
        project_client = mock.MagicMock
        project_client.audit_config = {}
        project_client.projects = {}

        assert len(_run(project_client)) == 0

    def test_public_prefix_without_secret_is_pass(self):
        project_client = mock.MagicMock
        project_client.audit_config = {}
        project_client.projects = {
            PROJECT_ID: _project(
                [
                    _env("NEXT_PUBLIC_SITE_URL"),
                    _env("NEXT_PUBLIC_SUPABASE_ANON_KEY_ENABLED"),
                    _env("DATABASE_PASSWORD", type="sensitive"),
                ]
            )
        }

        result = _run(project_client)
        assert len(result) == 1
        assert result[0].resource_id == PROJECT_ID
        assert result[0].resource_name == PROJECT_NAME
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Project {PROJECT_NAME} has no secret-like environment variables exposed to the browser through a public prefix."
        )
        assert result[0].team_id == TEAM_ID

    def test_public_prefix_with_secret_suffix_is_fail(self):
        project_client = mock.MagicMock
        project_client.audit_config = {}
        project_client.projects = {
            PROJECT_ID: _project(
                [
                    _env("NEXT_PUBLIC_SITE_URL"),
                    _env("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"),
                    _env("VITE_STRIPE_SECRET", type="plain"),
                ]
            )
        }

        result = _run(project_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Project {PROJECT_NAME} has 2 secret-like environment variable(s) exposed to the browser through a public prefix: NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY, VITE_STRIPE_SECRET."
        )

    def test_public_prefix_with_sensitive_type_is_fail(self):
        project_client = mock.MagicMock
        project_client.audit_config = {}
        project_client.projects = {
            PROJECT_ID: _project([_env("REACT_APP_BACKEND", type="sensitive")])
        }

        result = _run(project_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "REACT_APP_BACKEND" in result[0].status_extended

    def test_custom_prefixes_and_suffixes(self):
        project_client = mock.MagicMock
        project_client.audit_config = {
            "public_env_prefixes": ["ASTRO_"],
            "secret_suffixes": ["_CREDENTIAL"],
        }
        project_client.projects = {
            PROJECT_ID: _project(
                [
                    _env("NEXT_PUBLIC_API_KEY"),
                    _env("ASTRO_DB_CREDENTIAL"),
                ]
            )
        }

        result = _run(project_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Project {PROJECT_NAME} has 1 secret-like environment variable(s) exposed to the browser through a public prefix: ASTRO_DB_CREDENTIAL."
        )
