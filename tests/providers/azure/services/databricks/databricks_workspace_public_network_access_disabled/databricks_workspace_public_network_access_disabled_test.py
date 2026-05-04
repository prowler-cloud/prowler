from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_databricks_workspace_public_network_access_disabled:
    def test_no_subscriptions(self):
        databricks_client = mock.MagicMock

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

            databricks_client.workspaces = {}

            check = databricks_workspace_public_network_access_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_pass(self):
        databricks_client = mock.MagicMock

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
            from prowler.providers.azure.services.databricks.databricks_service import DatabricksWorkspace

            databricks_client.workspaces = {AZURE_SUBSCRIPTION_ID: {"/sub/rg/item1": DatabricksWorkspace(id="/sub/rg/workspace1", name="test-workspace", location="eastus", public_network_access="Disabled")}}

            check = databricks_workspace_public_network_access_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_fail(self):
        databricks_client = mock.MagicMock

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
            from prowler.providers.azure.services.databricks.databricks_service import DatabricksWorkspace

            databricks_client.workspaces = {AZURE_SUBSCRIPTION_ID: {"/sub/rg/item1": DatabricksWorkspace(id="/sub/rg/workspace1", name="test-workspace", location="eastus", public_network_access="Enabled")}}

            check = databricks_workspace_public_network_access_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
