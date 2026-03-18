from unittest import mock

from prowler.providers.vercel.services.deployment.deployment_service import (
    VercelDeployment,
)
from tests.providers.vercel.vercel_fixtures import (
    DEPLOYMENT_ID,
    PROJECT_ID,
    PROJECT_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)


class Test_deployment_preview_not_publicly_accessible:
    def test_no_deployments(self):
        deployment_client = mock.MagicMock
        deployment_client.deployments = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.deployment.deployment_preview_not_publicly_accessible.deployment_preview_not_publicly_accessible.deployment_client",
                new=deployment_client,
            ),
        ):
            from prowler.providers.vercel.services.deployment.deployment_preview_not_publicly_accessible.deployment_preview_not_publicly_accessible import (
                deployment_preview_not_publicly_accessible,
            )

            check = deployment_preview_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_preview_protected(self):
        deployment_client = mock.MagicMock
        deployment_client.deployments = {
            DEPLOYMENT_ID: VercelDeployment(
                id=DEPLOYMENT_ID,
                name="my-app-abc123",
                target="preview",
                deployment_protection="standard",
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.deployment.deployment_preview_not_publicly_accessible.deployment_preview_not_publicly_accessible.deployment_client",
                new=deployment_client,
            ),
        ):
            from prowler.providers.vercel.services.deployment.deployment_preview_not_publicly_accessible.deployment_preview_not_publicly_accessible import (
                deployment_preview_not_publicly_accessible,
            )

            check = deployment_preview_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == DEPLOYMENT_ID
            assert result[0].resource_name == "my-app-abc123"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Preview deployment my-app-abc123 ({DEPLOYMENT_ID}) has deployment protection configured."
            )
            assert result[0].team_id == TEAM_ID

    def test_preview_not_protected(self):
        deployment_client = mock.MagicMock
        deployment_client.deployments = {
            DEPLOYMENT_ID: VercelDeployment(
                id=DEPLOYMENT_ID,
                name="my-app-abc123",
                target="preview",
                deployment_protection=None,
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.deployment.deployment_preview_not_publicly_accessible.deployment_preview_not_publicly_accessible.deployment_client",
                new=deployment_client,
            ),
        ):
            from prowler.providers.vercel.services.deployment.deployment_preview_not_publicly_accessible.deployment_preview_not_publicly_accessible import (
                deployment_preview_not_publicly_accessible,
            )

            check = deployment_preview_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == DEPLOYMENT_ID
            assert result[0].resource_name == "my-app-abc123"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Preview deployment my-app-abc123 ({DEPLOYMENT_ID}) does not have deployment protection configured and is publicly accessible."
            )
            assert result[0].team_id == TEAM_ID

    def test_production_deployment_skipped(self):
        deployment_client = mock.MagicMock
        deployment_client.deployments = {
            DEPLOYMENT_ID: VercelDeployment(
                id=DEPLOYMENT_ID,
                name="my-app-abc123",
                target="production",
                deployment_protection="standard",
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.deployment.deployment_preview_not_publicly_accessible.deployment_preview_not_publicly_accessible.deployment_client",
                new=deployment_client,
            ),
        ):
            from prowler.providers.vercel.services.deployment.deployment_preview_not_publicly_accessible.deployment_preview_not_publicly_accessible import (
                deployment_preview_not_publicly_accessible,
            )

            check = deployment_preview_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0
