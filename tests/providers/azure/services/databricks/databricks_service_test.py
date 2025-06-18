from unittest.mock import patch

from prowler.providers.azure.services.databricks.databricks_service import (
    Databricks,
    DatabricksWorkspace,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_databricks_get_workspaces(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "test-workspace-id": DatabricksWorkspace(
                id="test-workspace-id",
                name="test-workspace",
                location="eastus",
                custom_managed_vnet_id="test-vnet-id",
            )
        }
    }


@patch(
    "prowler.providers.azure.services.databricks.databricks_service.Databricks._get_workspaces",
    new=mock_databricks_get_workspaces,
)
class Test_Databricks_Service:
    def test_get_client(self):
        databricks = Databricks(set_mocked_azure_provider())
        assert (
            databricks.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "AzureDatabricksManagementClient"
        )

    def test_get_workspaces(self):
        databricks = Databricks(set_mocked_azure_provider())
        assert (
            databricks.workspaces[AZURE_SUBSCRIPTION_ID][
                "test-workspace-id"
            ].__class__.__name__
            == "DatabricksWorkspace"
        )
        workspace = databricks.workspaces[AZURE_SUBSCRIPTION_ID]["test-workspace-id"]
        assert workspace.id == "test-workspace-id"
        assert workspace.name == "test-workspace"
        assert workspace.location == "eastus"
        assert workspace.custom_managed_vnet_id == "test-vnet-id"
