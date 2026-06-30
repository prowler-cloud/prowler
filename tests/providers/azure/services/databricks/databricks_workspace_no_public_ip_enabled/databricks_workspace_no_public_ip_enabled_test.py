from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.databricks.databricks_service import (
    DatabricksWorkspace,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_databricks_workspace_no_public_ip_enabled:
    def test_databricks_no_workspaces(self):
        databricks_client = mock.MagicMock
        databricks_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        databricks_client.workspaces = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.databricks.databricks_workspace_no_public_ip_enabled.databricks_workspace_no_public_ip_enabled.databricks_client",
                new=databricks_client,
            ),
        ):
            from prowler.providers.azure.services.databricks.databricks_workspace_no_public_ip_enabled.databricks_workspace_no_public_ip_enabled import (
                databricks_workspace_no_public_ip_enabled,
            )

            check = databricks_workspace_no_public_ip_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_databricks_workspace_no_public_ip_disabled(self):
        workspace_id = str(uuid4())
        workspace_name = "test-workspace"
        databricks_client = mock.MagicMock
        databricks_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        databricks_client.workspaces = {
            AZURE_SUBSCRIPTION_ID: {
                workspace_id: DatabricksWorkspace(
                    id=workspace_id,
                    name=workspace_name,
                    location="eastus",
                    no_public_ip_enabled=False,
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.databricks.databricks_workspace_no_public_ip_enabled.databricks_workspace_no_public_ip_enabled.databricks_client",
                new=databricks_client,
            ),
        ):
            from prowler.providers.azure.services.databricks.databricks_workspace_no_public_ip_enabled.databricks_workspace_no_public_ip_enabled import (
                databricks_workspace_no_public_ip_enabled,
            )

            check = databricks_workspace_no_public_ip_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Databricks workspace {workspace_name} in subscription {AZURE_SUBSCRIPTION_DISPLAY} does not have secure cluster connectivity (no public IP) enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == workspace_name
            assert result[0].resource_id == workspace_id
            assert result[0].location == "eastus"

    def test_databricks_workspace_no_public_ip_enabled(self):
        workspace_id = str(uuid4())
        workspace_name = "test-workspace"
        databricks_client = mock.MagicMock
        databricks_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        databricks_client.workspaces = {
            AZURE_SUBSCRIPTION_ID: {
                workspace_id: DatabricksWorkspace(
                    id=workspace_id,
                    name=workspace_name,
                    location="eastus",
                    no_public_ip_enabled=True,
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.databricks.databricks_workspace_no_public_ip_enabled.databricks_workspace_no_public_ip_enabled.databricks_client",
                new=databricks_client,
            ),
        ):
            from prowler.providers.azure.services.databricks.databricks_workspace_no_public_ip_enabled.databricks_workspace_no_public_ip_enabled import (
                databricks_workspace_no_public_ip_enabled,
            )

            check = databricks_workspace_no_public_ip_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Databricks workspace {workspace_name} in subscription {AZURE_SUBSCRIPTION_DISPLAY} has secure cluster connectivity (no public IP) enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == workspace_name
            assert result[0].resource_id == workspace_id
            assert result[0].location == "eastus"

    def test_databricks_workspace_no_public_ip_not_reported(self):
        workspace_id = str(uuid4())
        workspace_name = "test-workspace"
        databricks_client = mock.MagicMock
        databricks_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        databricks_client.workspaces = {
            AZURE_SUBSCRIPTION_ID: {
                workspace_id: DatabricksWorkspace(
                    id=workspace_id,
                    name=workspace_name,
                    location="eastus",
                    no_public_ip_enabled=None,
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.databricks.databricks_workspace_no_public_ip_enabled.databricks_workspace_no_public_ip_enabled.databricks_client",
                new=databricks_client,
            ),
        ):
            from prowler.providers.azure.services.databricks.databricks_workspace_no_public_ip_enabled.databricks_workspace_no_public_ip_enabled import (
                databricks_workspace_no_public_ip_enabled,
            )

            check = databricks_workspace_no_public_ip_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"Databricks workspace {workspace_name} in subscription {AZURE_SUBSCRIPTION_DISPLAY} does not expose secure cluster connectivity (no public IP) settings (for example, serverless workspaces have no public-IP cluster nodes); verify the network configuration manually."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == workspace_name
            assert result[0].resource_id == workspace_id
            assert result[0].location == "eastus"
