from unittest import mock

from prowler.providers.vercel.services.project.project_service import VercelProject
from tests.providers.vercel.vercel_fixtures import (
    PROJECT_ID,
    PROJECT_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)


class Test_project_auto_expose_system_env_disabled:
    def test_no_projects(self):
        project_client = mock.MagicMock
        project_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_auto_expose_system_env_disabled.project_auto_expose_system_env_disabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_auto_expose_system_env_disabled.project_auto_expose_system_env_disabled import (
                project_auto_expose_system_env_disabled,
            )

            check = project_auto_expose_system_env_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_auto_expose_disabled(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                auto_expose_system_envs=False,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_auto_expose_system_env_disabled.project_auto_expose_system_env_disabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_auto_expose_system_env_disabled.project_auto_expose_system_env_disabled import (
                project_auto_expose_system_env_disabled,
            )

            check = project_auto_expose_system_env_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} does not automatically expose system environment variables to the build process."
            )
            assert result[0].team_id == TEAM_ID

    def test_auto_expose_enabled(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                auto_expose_system_envs=True,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_auto_expose_system_env_disabled.project_auto_expose_system_env_disabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_auto_expose_system_env_disabled.project_auto_expose_system_env_disabled import (
                project_auto_expose_system_env_disabled,
            )

            check = project_auto_expose_system_env_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} automatically exposes system environment variables to the build process."
            )
            assert result[0].team_id == TEAM_ID
