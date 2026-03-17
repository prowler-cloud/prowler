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


class Test_project_environment_no_overly_broad_target:
    def test_no_projects(self):
        project_client = mock.MagicMock
        project_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_environment_no_overly_broad_target.project_environment_no_overly_broad_target.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_no_overly_broad_target.project_environment_no_overly_broad_target import (
                project_environment_no_overly_broad_target,
            )

            check = project_environment_no_overly_broad_target()
            result = check.execute()
            assert len(result) == 0

    def test_no_broad_vars(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                environment_variables=[
                    VercelEnvironmentVariable(
                        id="env_001",
                        key="DATABASE_URL",
                        type="encrypted",
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
                "prowler.providers.vercel.services.project.project_environment_no_overly_broad_target.project_environment_no_overly_broad_target.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_no_overly_broad_target.project_environment_no_overly_broad_target import (
                project_environment_no_overly_broad_target,
            )

            check = project_environment_no_overly_broad_target()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert "no environment variables targeting" in result[0].status_extended

    def test_var_targets_all_envs(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                environment_variables=[
                    VercelEnvironmentVariable(
                        id="env_002",
                        key="SHARED_VAR",
                        type="plain",
                        target=["production", "preview", "development"],
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
                "prowler.providers.vercel.services.project.project_environment_no_overly_broad_target.project_environment_no_overly_broad_target.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_no_overly_broad_target.project_environment_no_overly_broad_target import (
                project_environment_no_overly_broad_target,
            )

            check = project_environment_no_overly_broad_target()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert "targeting all three environments" in result[0].status_extended
