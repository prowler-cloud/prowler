from unittest import mock

from prowler.providers.vercel.services.project.project_service import (
    DeploymentProtectionConfig,
    VercelProject,
)
from tests.providers.vercel.vercel_fixtures import (
    PROJECT_ID,
    PROJECT_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)


class Test_project_deployment_protection_enabled:
    def test_no_projects(self):
        project_client = mock.MagicMock
        project_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_deployment_protection_enabled.project_deployment_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_deployment_protection_enabled.project_deployment_protection_enabled import (
                project_deployment_protection_enabled,
            )

            check = project_deployment_protection_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_deployment_protection_enabled(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                deployment_protection=DeploymentProtectionConfig(
                    level="standard",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_deployment_protection_enabled.project_deployment_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_deployment_protection_enabled.project_deployment_protection_enabled import (
                project_deployment_protection_enabled,
            )

            check = project_deployment_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} has deployment protection enabled with level 'standard' on preview deployments."
            )
            assert result[0].team_id == TEAM_ID

    def test_deployment_protection_disabled(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                deployment_protection=DeploymentProtectionConfig(
                    level="none",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_deployment_protection_enabled.project_deployment_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_deployment_protection_enabled.project_deployment_protection_enabled import (
                project_deployment_protection_enabled,
            )

            check = project_deployment_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} does not have deployment protection enabled on preview deployments."
            )
            assert result[0].team_id == TEAM_ID

    def test_deployment_protection_none(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                deployment_protection=None,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_deployment_protection_enabled.project_deployment_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_deployment_protection_enabled.project_deployment_protection_enabled import (
                project_deployment_protection_enabled,
            )

            check = project_deployment_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} does not have deployment protection enabled on preview deployments."
            )
            assert result[0].team_id == TEAM_ID
