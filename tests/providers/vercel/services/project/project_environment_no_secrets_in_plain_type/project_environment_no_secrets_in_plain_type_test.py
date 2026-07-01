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


class Test_project_environment_no_secrets_in_plain_type:
    def test_no_projects(self):
        project_client = mock.MagicMock
        project_client.audit_config = {}
        project_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.project.project_environment_no_secrets_in_plain_type.project_environment_no_secrets_in_plain_type.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_no_secrets_in_plain_type.project_environment_no_secrets_in_plain_type import (
                project_environment_no_secrets_in_plain_type,
            )

            check = project_environment_no_secrets_in_plain_type()
            result = check.execute()
            assert len(result) == 0

    def test_no_secret_keys_plain(self):
        project_client = mock.MagicMock
        project_client.audit_config = {}
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
                "prowler.providers.vercel.services.project.project_environment_no_secrets_in_plain_type.project_environment_no_secrets_in_plain_type.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_no_secrets_in_plain_type.project_environment_no_secrets_in_plain_type import (
                project_environment_no_secrets_in_plain_type,
            )

            check = project_environment_no_secrets_in_plain_type()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} has no secret-like environment variables stored as plain text."
            )
            assert result[0].team_id == TEAM_ID

    def test_secret_key_plain(self):
        project_client = mock.MagicMock
        project_client.audit_config = {}
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                environment_variables=[
                    VercelEnvironmentVariable(
                        id="env_002",
                        key="MY_API_KEY",
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
                "prowler.providers.vercel.services.project.project_environment_no_secrets_in_plain_type.project_environment_no_secrets_in_plain_type.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_no_secrets_in_plain_type.project_environment_no_secrets_in_plain_type import (
                project_environment_no_secrets_in_plain_type,
            )

            check = project_environment_no_secrets_in_plain_type()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} has 1 secret-like environment variable(s) stored as plain text: MY_API_KEY."
            )
            assert result[0].team_id == TEAM_ID

    def test_non_secret_key_plain(self):
        project_client = mock.MagicMock
        project_client.audit_config = {}
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
                "prowler.providers.vercel.services.project.project_environment_no_secrets_in_plain_type.project_environment_no_secrets_in_plain_type.project_client",
                new=project_client,
            ),
        ):
            from prowler.providers.vercel.services.project.project_environment_no_secrets_in_plain_type.project_environment_no_secrets_in_plain_type import (
                project_environment_no_secrets_in_plain_type,
            )

            check = project_environment_no_secrets_in_plain_type()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} has no secret-like environment variables stored as plain text."
            )
            assert result[0].team_id == TEAM_ID
