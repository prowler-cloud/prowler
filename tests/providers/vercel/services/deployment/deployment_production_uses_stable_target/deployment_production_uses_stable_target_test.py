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


class Test_deployment_production_uses_stable_target:
    def test_no_deployments(self):
        deployment_client = mock.MagicMock
        deployment_client.deployments = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.deployment.deployment_production_uses_stable_target.deployment_production_uses_stable_target.deployment_client",
                new=deployment_client,
            ),
        ):
            from prowler.providers.vercel.services.deployment.deployment_production_uses_stable_target.deployment_production_uses_stable_target import (
                deployment_production_uses_stable_target,
            )

            check = deployment_production_uses_stable_target()
            result = check.execute()
            assert len(result) == 0

    def test_stable_branch(self):
        deployment_client = mock.MagicMock
        deployment_client.deployments = {
            DEPLOYMENT_ID: VercelDeployment(
                id=DEPLOYMENT_ID,
                name="my-app-abc123",
                target="production",
                git_source={"branch": "main"},
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
            )
        }
        deployment_client.audit_config = {"stable_branches": ["main", "master"]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.deployment.deployment_production_uses_stable_target.deployment_production_uses_stable_target.deployment_client",
                new=deployment_client,
            ),
        ):
            from prowler.providers.vercel.services.deployment.deployment_production_uses_stable_target.deployment_production_uses_stable_target import (
                deployment_production_uses_stable_target,
            )

            check = deployment_production_uses_stable_target()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == DEPLOYMENT_ID
            assert result[0].resource_name == "my-app-abc123"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Production deployment my-app-abc123 ({DEPLOYMENT_ID}) is sourced from stable branch 'main'."
            )
            assert result[0].team_id == TEAM_ID

    def test_non_stable_branch(self):
        deployment_client = mock.MagicMock
        deployment_client.deployments = {
            DEPLOYMENT_ID: VercelDeployment(
                id=DEPLOYMENT_ID,
                name="my-app-abc123",
                target="production",
                git_source={"branch": "feature-xyz"},
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
            )
        }
        deployment_client.audit_config = {"stable_branches": ["main", "master"]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.deployment.deployment_production_uses_stable_target.deployment_production_uses_stable_target.deployment_client",
                new=deployment_client,
            ),
        ):
            from prowler.providers.vercel.services.deployment.deployment_production_uses_stable_target.deployment_production_uses_stable_target import (
                deployment_production_uses_stable_target,
            )

            check = deployment_production_uses_stable_target()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == DEPLOYMENT_ID
            assert result[0].resource_name == "my-app-abc123"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Production deployment my-app-abc123 ({DEPLOYMENT_ID}) is sourced from branch 'feature-xyz' instead of a configured stable branch (main, master)."
            )
            assert result[0].team_id == TEAM_ID

    def test_non_production_skipped(self):
        deployment_client = mock.MagicMock
        deployment_client.deployments = {
            DEPLOYMENT_ID: VercelDeployment(
                id=DEPLOYMENT_ID,
                name="my-app-abc123",
                target="preview",
                git_source={"branch": "feature-xyz"},
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
            )
        }
        deployment_client.audit_config = {"stable_branches": ["main", "master"]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.deployment.deployment_production_uses_stable_target.deployment_production_uses_stable_target.deployment_client",
                new=deployment_client,
            ),
        ):
            from prowler.providers.vercel.services.deployment.deployment_production_uses_stable_target.deployment_production_uses_stable_target import (
                deployment_production_uses_stable_target,
            )

            check = deployment_production_uses_stable_target()
            result = check.execute()
            assert len(result) == 0
