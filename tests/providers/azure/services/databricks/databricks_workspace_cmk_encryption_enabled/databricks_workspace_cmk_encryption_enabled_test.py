from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.databricks.databricks_service import (
    DatabricksWorkspace,
    ManagedDiskEncryption,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_databricks_workspace_cmk_encryption_enabled:
    def test_no_databricks_workspaces(self):
        databricks_client = mock.MagicMock
        databricks_client.workspaces = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.databricks.databricks_workspace_cmk_encryption_enabled.databricks_workspace_cmk_encryption_enabled.databricks_client",
                new=databricks_client,
            ),
        ):
            from prowler.providers.azure.services.databricks.databricks_workspace_cmk_encryption_enabled.databricks_workspace_cmk_encryption_enabled import (
                databricks_workspace_cmk_encryption_enabled,
            )

            check = databricks_workspace_cmk_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_databricks_workspace_cmk_encryption_disabled(self):
        workspace_id = str(uuid4())
        workspace_name = "test-workspace"

        databricks_client = mock.MagicMock
        databricks_client.workspaces = {
            AZURE_SUBSCRIPTION_ID: {
                workspace_id: DatabricksWorkspace(
                    id=workspace_id,
                    name=workspace_name,
                    location="eastus",
                    custom_managed_vnet_id=None,
                    managed_disk_encryption=None,
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.databricks.databricks_workspace_cmk_encryption_enabled.databricks_workspace_cmk_encryption_enabled.databricks_client",
                new=databricks_client,
            ),
        ):
            from prowler.providers.azure.services.databricks.databricks_workspace_cmk_encryption_enabled.databricks_workspace_cmk_encryption_enabled import (
                databricks_workspace_cmk_encryption_enabled,
            )

            check = databricks_workspace_cmk_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Databricks workspace {workspace_name} in subscription {AZURE_SUBSCRIPTION_ID} does not have customer-managed key (CMK) encryption enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == workspace_name
            assert result[0].resource_id == workspace_id
            assert result[0].location == "eastus"

    def test_databricks_workspace_cmk_encryption_enabled(self):
        workspace_id = str(uuid4())
        workspace_name = "test-workspace"
        key_name = "test-key"
        key_version = "test-version"
        key_vault_uri = "test-vault-uri"

        databricks_client = mock.MagicMock
        databricks_client.workspaces = {
            AZURE_SUBSCRIPTION_ID: {
                workspace_id: DatabricksWorkspace(
                    id=workspace_id,
                    name=workspace_name,
                    location="eastus",
                    custom_managed_vnet_id=None,
                    managed_disk_encryption=ManagedDiskEncryption(
                        key_name=key_name,
                        key_version=key_version,
                        key_vault_uri=key_vault_uri,
                    ),
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.databricks.databricks_workspace_cmk_encryption_enabled.databricks_workspace_cmk_encryption_enabled.databricks_client",
                new=databricks_client,
            ),
        ):
            from prowler.providers.azure.services.databricks.databricks_workspace_cmk_encryption_enabled.databricks_workspace_cmk_encryption_enabled import (
                databricks_workspace_cmk_encryption_enabled,
            )

            check = databricks_workspace_cmk_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Databricks workspace {workspace_name} in subscription {AZURE_SUBSCRIPTION_ID} has customer-managed key (CMK) encryption enabled with key {key_vault_uri}/{key_name}/{key_version}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == workspace_name
            assert result[0].resource_id == workspace_id
            assert result[0].location == "eastus"
