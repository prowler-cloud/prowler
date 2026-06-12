from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.databricks.databricks_service import (
    Databricks,
    DatabricksWorkspace,
    ManagedDiskEncryption,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
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


class Test_Databricks_get_workspaces:
    def test_get_workspaces_no_resource_groups(self):
        mock_workspace = MagicMock()
        mock_workspace.id = "ws-id-1"
        mock_workspace.name = "my-workspace"
        mock_workspace.location = "eastus"
        mock_workspace.parameters = None
        mock_workspace.encryption = None

        mock_client = MagicMock()
        mock_client.workspaces = MagicMock()
        mock_client.workspaces.list_by_subscription.return_value = [mock_workspace]

        with patch(
            "prowler.providers.azure.services.databricks.databricks_service.Databricks._get_workspaces",
            return_value={},
        ):
            databricks = Databricks(set_mocked_azure_provider())

        databricks.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        databricks.resource_groups = None

        result = databricks._get_workspaces()

        mock_client.workspaces.list_by_subscription.assert_called_once()
        mock_client.workspaces.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result
        assert "ws-id-1" in result[AZURE_SUBSCRIPTION_ID]

    def test_get_workspaces_with_resource_group(self):
        mock_workspace = MagicMock()
        mock_workspace.id = "ws-id-1"
        mock_workspace.name = "my-workspace"
        mock_workspace.location = "eastus"
        mock_workspace.parameters = None
        mock_workspace.encryption = None

        mock_client = MagicMock()
        mock_client.workspaces = MagicMock()
        mock_client.workspaces.list_by_resource_group.return_value = [mock_workspace]

        with patch(
            "prowler.providers.azure.services.databricks.databricks_service.Databricks._get_workspaces",
            return_value={},
        ):
            databricks = Databricks(set_mocked_azure_provider())

        databricks.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        databricks.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = databricks._get_workspaces()

        mock_client.workspaces.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.workspaces.list_by_subscription.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result
        assert "ws-id-1" in result[AZURE_SUBSCRIPTION_ID]

    def test_get_workspaces_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()
        mock_client.workspaces = MagicMock()

        with patch(
            "prowler.providers.azure.services.databricks.databricks_service.Databricks._get_workspaces",
            return_value={},
        ):
            databricks = Databricks(set_mocked_azure_provider())

        databricks.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        databricks.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = databricks._get_workspaces()

        mock_client.workspaces.list_by_resource_group.assert_not_called()
        mock_client.workspaces.list_by_subscription.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == {}

    def test_get_workspaces_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.workspaces = MagicMock()
        mock_client.workspaces.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.databricks.databricks_service.Databricks._get_workspaces",
            return_value={},
        ):
            databricks = Databricks(set_mocked_azure_provider())

        databricks.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        databricks.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = databricks._get_workspaces()

        assert mock_client.workspaces.list_by_resource_group.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_workspaces_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.workspaces = MagicMock()
        mock_client.workspaces.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.databricks.databricks_service.Databricks._get_workspaces",
            return_value={},
        ):
            databricks = Databricks(set_mocked_azure_provider())

        databricks.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        databricks.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        databricks._get_workspaces()

        mock_client.workspaces.list_by_resource_group.assert_called_once_with(
            resource_group_name="RG"
        )
