from unittest.mock import patch

from prowler.providers.azure.services.databricks.databricks_service import (
    Databricks,
    DatabricksWorkspace,
    ManagedDiskEncryption,
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
                managed_disk_encryption=ManagedDiskEncryption(
                    key_name="test-key",
                    key_version="test-version",
                    key_vault_uri="test-vault-uri",
                ),
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
        assert (
            workspace.managed_disk_encryption.__class__.__name__
            == "ManagedDiskEncryption"
        )
        assert workspace.managed_disk_encryption.key_name == "test-key"
        assert workspace.managed_disk_encryption.key_version == "test-version"
        assert workspace.managed_disk_encryption.key_vault_uri == "test-vault-uri"


def mock_databricks_get_workspaces_no_encryption(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "test-workspace-id": DatabricksWorkspace(
                id="test-workspace-id",
                name="test-workspace",
                location="eastus",
                custom_managed_vnet_id="test-vnet-id",
                managed_disk_encryption=None,
            )
        }
    }


@patch(
    "prowler.providers.azure.services.databricks.databricks_service.Databricks._get_workspaces",
    new=mock_databricks_get_workspaces_no_encryption,
)
class Test_Databricks_Service_No_Encryption:
    def test_get_workspaces_no_encryption(self):
        databricks = Databricks(set_mocked_azure_provider())
        workspace = databricks.workspaces[AZURE_SUBSCRIPTION_ID]["test-workspace-id"]
        assert workspace.id == "test-workspace-id"
        assert workspace.name == "test-workspace"
        assert workspace.location == "eastus"
        assert workspace.custom_managed_vnet_id == "test-vnet-id"
        assert workspace.managed_disk_encryption is None
