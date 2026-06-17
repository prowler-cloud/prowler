from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.databricks.databricks_service import (
    DatabricksWorkspace,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_databricks_workspace_public_network_access_disabled:
    def test_no_workspaces(self):
        databricks_client = mock.MagicMock
        databricks_client.workspaces = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.databricks.databricks_workspace_public_network_access_disabled.databricks_workspace_public_network_access_disabled.databricks_client",
                new=databricks_client,
            ),
        ):
            from prowler.providers.azure.services.databricks.databricks_workspace_public_network_access_disabled.databricks_workspace_public_network_access_disabled import (
                databricks_workspace_public_network_access_disabled,
            )

            check = databricks_workspace_public_network_access_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_pass(self):
        workspace_id = str(uuid4())
        workspace_name = "test-workspace"
        databricks_client = mock.MagicMock
        databricks_client.workspaces = {
            AZURE_SUBSCRIPTION_ID: {
                workspace_id: DatabricksWorkspace(
                    id=workspace_id,
                    name=workspace_name,
                    location="eastus",
                    public_network_access="Disabled",
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.databricks.databricks_workspace_public_network_access_disabled.databricks_workspace_public_network_access_disabled.databricks_client",
                new=databricks_client,
            ),
        ):
            from prowler.providers.azure.services.databricks.databricks_workspace_public_network_access_disabled.databricks_workspace_public_network_access_disabled import (
                databricks_workspace_public_network_access_disabled,
            )

            check = databricks_workspace_public_network_access_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Databricks workspace {workspace_name} from subscription {AZURE_SUBSCRIPTION_ID} has public network access disabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == workspace_name
            assert result[0].resource_id == workspace_id
            assert result[0].location == "eastus"

    def test_fail(self):
        workspace_id = str(uuid4())
        workspace_name = "test-workspace"
        databricks_client = mock.MagicMock
        databricks_client.workspaces = {
            AZURE_SUBSCRIPTION_ID: {
                workspace_id: DatabricksWorkspace(
                    id=workspace_id,
                    name=workspace_name,
                    location="eastus",
                    public_network_access="Enabled",
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.databricks.databricks_workspace_public_network_access_disabled.databricks_workspace_public_network_access_disabled.databricks_client",
                new=databricks_client,
            ),
        ):
            from prowler.providers.azure.services.databricks.databricks_workspace_public_network_access_disabled.databricks_workspace_public_network_access_disabled import (
                databricks_workspace_public_network_access_disabled,
            )

            check = databricks_workspace_public_network_access_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Databricks workspace {workspace_name} from subscription {AZURE_SUBSCRIPTION_ID} has public network access enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == workspace_name
            assert result[0].resource_id == workspace_id
            assert result[0].location == "eastus"
