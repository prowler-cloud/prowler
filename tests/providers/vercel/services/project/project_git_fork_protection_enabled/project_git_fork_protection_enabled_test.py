from unittest import mock

from prowler.providers.vercel.services.project.project_service import VercelProject
from tests.providers.vercel.vercel_fixtures import (
    PROJECT_ID,
    PROJECT_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)


class Test_project_git_fork_protection_enabled:
    def test_no_projects(self):
        project_client = mock.MagicMock
        project_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_git_fork_protection_enabled.project_git_fork_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_git_fork_protection_enabled.project_git_fork_protection_enabled import (
                project_git_fork_protection_enabled,
            )

            check = project_git_fork_protection_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_fork_protection_enabled(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                git_fork_protection=True,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_git_fork_protection_enabled.project_git_fork_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_git_fork_protection_enabled.project_git_fork_protection_enabled import (
                project_git_fork_protection_enabled,
            )

            check = project_git_fork_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} has Git fork protection enabled, preventing untrusted forks from accessing secrets."
            )
            assert result[0].team_id == TEAM_ID

    def test_fork_protection_disabled(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                git_fork_protection=False,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_git_fork_protection_enabled.project_git_fork_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_git_fork_protection_enabled.project_git_fork_protection_enabled import (
                project_git_fork_protection_enabled,
            )

            check = project_git_fork_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} does not have Git fork protection enabled, allowing forks to access environment variables and trigger deployments."
            )
            assert result[0].team_id == TEAM_ID
