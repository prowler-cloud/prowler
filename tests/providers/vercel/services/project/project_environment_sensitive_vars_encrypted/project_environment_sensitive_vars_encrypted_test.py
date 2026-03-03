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


class Test_project_environment_sensitive_vars_encrypted:
    def test_no_projects(self):
        project_client = mock.MagicMock
        project_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_environment_sensitive_vars_encrypted.project_environment_sensitive_vars_encrypted.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_sensitive_vars_encrypted.project_environment_sensitive_vars_encrypted import (
                project_environment_sensitive_vars_encrypted,
            )

            check = project_environment_sensitive_vars_encrypted()
            result = check.execute()
            assert len(result) == 0

    def test_all_sensitive_vars_encrypted(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                environment_variables=[
                    VercelEnvironmentVariable(
                        id="env_001",
                        key="DATABASE_PASSWORD",
                        type="encrypted",
                        project_id=PROJECT_ID,
                    ),
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_environment_sensitive_vars_encrypted.project_environment_sensitive_vars_encrypted.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_sensitive_vars_encrypted.project_environment_sensitive_vars_encrypted import (
                project_environment_sensitive_vars_encrypted,
            )

            check = project_environment_sensitive_vars_encrypted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert "properly encrypted" in result[0].status_extended

    def test_sensitive_var_plain_text(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                environment_variables=[
                    VercelEnvironmentVariable(
                        id="env_002",
                        key="API_KEY",
                        type="plain",
                        project_id=PROJECT_ID,
                    ),
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_environment_sensitive_vars_encrypted.project_environment_sensitive_vars_encrypted.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_sensitive_vars_encrypted.project_environment_sensitive_vars_encrypted import (
                project_environment_sensitive_vars_encrypted,
            )

            check = project_environment_sensitive_vars_encrypted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "plain text" in result[0].status_extended
            assert "API_KEY" in result[0].status_extended

    def test_no_sensitive_vars(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                environment_variables=[
                    VercelEnvironmentVariable(
                        id="env_003",
                        key="APP_NAME",
                        type="plain",
                        project_id=PROJECT_ID,
                    ),
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_environment_sensitive_vars_encrypted.project_environment_sensitive_vars_encrypted.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_sensitive_vars_encrypted.project_environment_sensitive_vars_encrypted import (
                project_environment_sensitive_vars_encrypted,
            )

            check = project_environment_sensitive_vars_encrypted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "properly encrypted" in result[0].status_extended
