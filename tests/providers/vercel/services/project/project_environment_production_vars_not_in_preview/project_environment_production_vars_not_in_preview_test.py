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


class Test_project_environment_production_vars_not_in_preview:
    def test_no_projects(self):
        project_client = mock.MagicMock
        project_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_environment_production_vars_not_in_preview.project_environment_production_vars_not_in_preview.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_production_vars_not_in_preview.project_environment_production_vars_not_in_preview import (
                project_environment_production_vars_not_in_preview,
            )

            check = project_environment_production_vars_not_in_preview()
            result = check.execute()
            assert len(result) == 0

    def test_prod_only_secret(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                environment_variables=[
                    VercelEnvironmentVariable(
                        id="env_001",
                        key="DB_PASSWORD",
                        type="secret",
                        target=["production"],
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
                "prowler.providers.vercel.services.project.project_environment_production_vars_not_in_preview.project_environment_production_vars_not_in_preview.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_production_vars_not_in_preview.project_environment_production_vars_not_in_preview import (
                project_environment_production_vars_not_in_preview,
            )

            check = project_environment_production_vars_not_in_preview()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} has no sensitive production environment variables leaking to preview deployments."
            )
            assert result[0].team_id == TEAM_ID

    def test_prod_and_preview_secret(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                environment_variables=[
                    VercelEnvironmentVariable(
                        id="env_002",
                        key="DB_PASSWORD",
                        type="secret",
                        target=["production", "preview"],
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
                "prowler.providers.vercel.services.project.project_environment_production_vars_not_in_preview.project_environment_production_vars_not_in_preview.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_production_vars_not_in_preview.project_environment_production_vars_not_in_preview import (
                project_environment_production_vars_not_in_preview,
            )

            check = project_environment_production_vars_not_in_preview()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} has 1 sensitive production environment variable(s) also targeting preview: DB_PASSWORD."
            )
            assert result[0].team_id == TEAM_ID

    def test_prod_and_preview_plain(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                environment_variables=[
                    VercelEnvironmentVariable(
                        id="env_003",
                        key="APP_URL",
                        type="plain",
                        target=["production", "preview"],
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
                "prowler.providers.vercel.services.project.project_environment_production_vars_not_in_preview.project_environment_production_vars_not_in_preview.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_production_vars_not_in_preview.project_environment_production_vars_not_in_preview import (
                project_environment_production_vars_not_in_preview,
            )

            check = project_environment_production_vars_not_in_preview()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} has no sensitive production environment variables leaking to preview deployments."
            )
            assert result[0].team_id == TEAM_ID
