from unittest import mock

from prowler.providers.vercel.services.project.project_service import VercelProject
from tests.providers.vercel.vercel_fixtures import (
    PROJECT_ID,
    PROJECT_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)


class Test_project_password_protection_enabled:
    def test_no_projects(self):
        project_client = mock.MagicMock
        project_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_password_protection_enabled.project_password_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_password_protection_enabled.project_password_protection_enabled import (
                project_password_protection_enabled,
            )

            check = project_password_protection_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_password_protection_configured(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                password_protection={"deploymentType": "all"},
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_password_protection_enabled.project_password_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_password_protection_enabled.project_password_protection_enabled import (
                project_password_protection_enabled,
            )

            check = project_password_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} has password protection configured to restrict access to deployments."
            )
            assert result[0].team_id == TEAM_ID

    def test_empty_dict_password_protection(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                password_protection={},
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_password_protection_enabled.project_password_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_password_protection_enabled.project_password_protection_enabled import (
                project_password_protection_enabled,
            )

            check = project_password_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} does not have password protection configured for deployments."
            )
            assert result[0].team_id == TEAM_ID

    def test_no_password_protection(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                password_protection=None,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_password_protection_enabled.project_password_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_password_protection_enabled.project_password_protection_enabled import (
                project_password_protection_enabled,
            )

            check = project_password_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} does not have password protection configured for deployments."
            )
            assert result[0].team_id == TEAM_ID

    def test_no_password_protection_hobby_plan(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                password_protection=None,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(billing_plan="hobby"),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_password_protection_enabled.project_password_protection_enabled.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_password_protection_enabled.project_password_protection_enabled import (
                project_password_protection_enabled,
            )

            check = project_password_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} does not have password protection configured for deployments. This may be expected because password protection is not available on the Vercel Hobby plan."
            )
            assert result[0].team_id == TEAM_ID
