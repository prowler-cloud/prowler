from unittest import mock

from prowler.providers.azure.services.databricks.databricks_service import (
    DatabricksWorkspace,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "databricks_workspace_uses_private_endpoint"
CHECK_PATH = f"prowler.providers.azure.services.databricks.{CHECK}.{CHECK}"
WORKSPACE_NAME = "test-workspace"
WORKSPACE_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Databricks/workspaces/{WORKSPACE_NAME}"
PREFIX = f"Databricks workspace {WORKSPACE_NAME} in subscription {AZURE_SUBSCRIPTION_DISPLAY}"


def build_workspace(
    statuses: list[str], workspace_id: str = WORKSPACE_ID, name: str = WORKSPACE_NAME
) -> DatabricksWorkspace:
    return DatabricksWorkspace(
        id=workspace_id,
        name=name,
        location="eastus",
        private_endpoint_connection_statuses=statuses,
    )


def run_check(workspaces):
    databricks_client = mock.MagicMock()
    databricks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    databricks_client.workspaces = workspaces
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.databricks_client", new=databricks_client),
    ):
        from prowler.providers.azure.services.databricks.databricks_workspace_uses_private_endpoint.databricks_workspace_uses_private_endpoint import (
            databricks_workspace_uses_private_endpoint,
        )

        return databricks_workspace_uses_private_endpoint().execute()


class Test_databricks_workspace_uses_private_endpoint:
    def test_no_workspaces(self):
        assert run_check({}) == []

    def test_no_private_endpoints(self):
        result = run_check({AZURE_SUBSCRIPTION_ID: {WORKSPACE_ID: build_workspace([])}})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{PREFIX} has no approved private endpoint connection."
        )
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
        assert result[0].resource_id == WORKSPACE_ID
        assert result[0].resource_name == WORKSPACE_NAME
        assert result[0].location == "eastus"

    def test_only_unapproved_private_endpoints(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    WORKSPACE_ID: build_workspace(
                        ["Pending", "Rejected", "Disconnected"]
                    )
                }
            }
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{PREFIX} has no approved private endpoint connection."
        )

    def test_approved_private_endpoint(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    WORKSPACE_ID: build_workspace(["Pending", "Approved"])
                }
            }
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"{PREFIX} has an approved private endpoint connection."
        )
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
        assert result[0].resource_id == WORKSPACE_ID
        assert result[0].resource_name == WORKSPACE_NAME
        assert result[0].location == "eastus"

    def test_one_finding_per_workspace(self):
        other_id = WORKSPACE_ID.replace(WORKSPACE_NAME, "other-workspace")
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    WORKSPACE_ID: build_workspace(["Approved"]),
                    other_id: build_workspace([], other_id, "other-workspace"),
                }
            }
        )
        assert [(r.resource_name, r.status) for r in result] == [
            (WORKSPACE_NAME, "PASS"),
            ("other-workspace", "FAIL"),
        ]
