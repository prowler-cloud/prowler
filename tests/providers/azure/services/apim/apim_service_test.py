from datetime import timedelta
from unittest import TestCase, mock
from unittest.mock import patch

from azure.mgmt.loganalytics.models import Workspace
from azure.mgmt.monitor.models import DiagnosticSettingsResource
from azure.monitor.query import LogsQueryResult

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)

# Define constants for reusable mock data
APIM_INSTANCE_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim1"
APIM_INSTANCE_NAME = "apim1"
LOCATION = "West US"
RESOURCE_GROUP = "rg"
WORKSPACE_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourcegroups/rg/providers/microsoft.operationalinsights/workspaces/loganalytics"
WORKSPACE_CUSTOMER_ID = "12345678-1234-1234-1234-1234567890ab"


def mock_apim_get_instances(_):
    """Mock function to replace APIM._get_instances."""
    from prowler.providers.azure.services.apim.apim_service import APIMInstance

    return {
        AZURE_SUBSCRIPTION_ID: [
            APIMInstance(
                id=APIM_INSTANCE_ID,
                name=APIM_INSTANCE_NAME,
                location=LOCATION,
                log_analytics_workspace_id=WORKSPACE_ID,
            )
        ]
    }


class Test_APIM_Service(TestCase):
    def test_get_client(self):
        """Test that the APIM service client is created correctly."""
        mock_provider = mock.MagicMock()
        mock_provider.identity = mock.MagicMock()
        with (
            patch(
                "prowler.providers.azure.azure_provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.azure.services.apim.apim_service.APIM._get_instances",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.apim.apim_service import APIM

            apim = APIM(set_mocked_azure_provider())
            self.assertEqual(
                apim.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__,
                "ApiManagementClient",
            )

    def test_get_subscriptions(self):
        """Test that subscriptions are retrieved correctly."""
        mock_provider = mock.MagicMock()
        mock_provider.identity = mock.MagicMock()
        with (
            patch(
                "prowler.providers.azure.azure_provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.azure.services.apim.apim_service.APIM._get_instances",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.apim.apim_service import APIM

            apim = APIM(set_mocked_azure_provider())
            self.assertEqual(apim.subscriptions.__class__.__name__, "dict")

    def test_get_instances(self):
        """Test that APIM instances are retrieved and parsed correctly."""
        mock_provider = mock.MagicMock()
        mock_provider.identity = mock.MagicMock()
        with (
            patch(
                "prowler.providers.azure.azure_provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.azure.services.apim.apim_service.APIM._get_instances",
                new=mock_apim_get_instances,
            ),
        ):
            from prowler.providers.azure.services.apim.apim_service import APIM

            apim = APIM(set_mocked_azure_provider())
            self.assertEqual(len(apim.instances), 1)
            self.assertEqual(len(apim.instances[AZURE_SUBSCRIPTION_ID]), 1)
            instance = apim.instances[AZURE_SUBSCRIPTION_ID][0]
            self.assertEqual(instance.id, APIM_INSTANCE_ID)
            self.assertEqual(instance.name, APIM_INSTANCE_NAME)
            self.assertEqual(instance.location, LOCATION)
            self.assertEqual(instance.log_analytics_workspace_id, WORKSPACE_ID)

    def test_get_log_analytics_workspace_id_success(self):
        """Test retrieving a Log Analytics workspace ID successfully."""
        mock_provider = mock.MagicMock()
        mock_provider.identity = mock.MagicMock()
        with patch(
            "prowler.providers.azure.azure_provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            from prowler.providers.azure.services.apim.apim_service import APIM

            with (
                patch(
                    "prowler.providers.azure.services.apim.apim_service.APIM._get_instances",
                    return_value={},
                ),
                patch(
                    "prowler.providers.azure.services.apim.apim_service.monitor_client"
                ) as mock_monitor_client,
            ):
                apim = APIM(set_mocked_azure_provider())
                mock_log_setting = mock.MagicMock(enabled=True, category="GatewayLogs")
                mock_setting = DiagnosticSettingsResource(
                    workspace_id=WORKSPACE_ID, logs=[mock_log_setting]
                )
                mock_monitor_client.diagnostic_settings_with_uri.return_value = [
                    mock_setting
                ]
                workspace_id = apim._get_log_analytics_workspace_id(
                    APIM_INSTANCE_ID, AZURE_SUBSCRIPTION_ID
                )
                self.assertEqual(workspace_id, WORKSPACE_ID)

    def test_get_log_analytics_workspace_id_not_enabled(self):
        """Test that no workspace ID is returned if GatewayLogs are not enabled."""
        mock_provider = mock.MagicMock()
        mock_provider.identity = mock.MagicMock()
        with patch(
            "prowler.providers.azure.azure_provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            from prowler.providers.azure.services.apim.apim_service import APIM

            with (
                patch(
                    "prowler.providers.azure.services.apim.apim_service.APIM._get_instances",
                    return_value={},
                ),
                patch(
                    "prowler.providers.azure.services.apim.apim_service.monitor_client"
                ) as mock_monitor_client,
            ):
                apim = APIM(set_mocked_azure_provider())
                mock_log_setting = mock.MagicMock(enabled=False, category="GatewayLogs")
                mock_setting = DiagnosticSettingsResource(
                    workspace_id=WORKSPACE_ID, logs=[mock_log_setting]
                )
                mock_monitor_client.diagnostic_settings_with_uri.return_value = [
                    mock_setting
                ]
                workspace_id = apim._get_log_analytics_workspace_id(
                    APIM_INSTANCE_ID, AZURE_SUBSCRIPTION_ID
                )
                self.assertIsNone(workspace_id)

    def test_get_workspace_customer_id_success(self):
        """Test retrieving a workspace customer ID successfully."""
        mock_provider = mock.MagicMock()
        mock_provider.identity = mock.MagicMock()
        with patch(
            "prowler.providers.azure.azure_provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            from prowler.providers.azure.services.apim.apim_service import APIM

            with (
                patch(
                    "prowler.providers.azure.services.apim.apim_service.APIM._get_instances",
                    return_value={},
                ),
                patch(
                    "prowler.providers.azure.services.apim.apim_service.loganalytics_client"
                ) as mock_loganalytics_client,
            ):
                apim = APIM(set_mocked_azure_provider())
                mock_workspace = Workspace(location=LOCATION)
                # Set customer_id after creation since it's readonly
                mock_workspace.customer_id = WORKSPACE_CUSTOMER_ID

                # Properly mock the nested client structure
                mock_client = mock.MagicMock()
                mock_workspaces = mock.MagicMock()
                mock_workspaces.get.return_value = mock_workspace
                mock_client.workspaces = mock_workspaces
                mock_loganalytics_client.clients = {AZURE_SUBSCRIPTION_ID: mock_client}

                customer_id = apim._get_workspace_customer_id(
                    AZURE_SUBSCRIPTION_ID, WORKSPACE_ID
                )
                self.assertEqual(customer_id, WORKSPACE_CUSTOMER_ID)

    def test_query_logs_success(self):
        """Test querying logs successfully."""
        mock_provider = mock.MagicMock()
        mock_provider.identity = mock.MagicMock()
        with patch(
            "prowler.providers.azure.azure_provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            from prowler.providers.azure.services.apim.apim_service import APIM

            with (
                patch(
                    "prowler.providers.azure.services.apim.apim_service.APIM._get_instances",
                    return_value={},
                ),
                patch(
                    "prowler.providers.azure.services.apim.apim_service.logsquery_client"
                ) as mock_logsquery_client,
            ):
                apim = APIM(set_mocked_azure_provider())
                # Create a mock table with the expected structure for LogsQueryLogEntry
                mock_table = mock.MagicMock()
                mock_table.columns = [
                    "TimeGenerated",
                    "OperationId",
                    "CallerIpAddress",
                    "CorrelationId",
                ]
                from datetime import datetime

                mock_table.rows = [
                    [
                        datetime.fromisoformat("2024-01-01T10:00:00+00:00"),
                        "test-operation",
                        "192.168.1.100",
                        "test-correlation",
                    ]
                ]

                mock_response = LogsQueryResult(tables=[mock_table], status="Success")

                # Properly mock the nested client structure
                mock_client = mock.MagicMock()
                mock_client.query_workspace.return_value = mock_response
                mock_logsquery_client.clients = {AZURE_SUBSCRIPTION_ID: mock_client}

                result = apim.query_logs(
                    AZURE_SUBSCRIPTION_ID,
                    "query",
                    timedelta(minutes=60),
                    WORKSPACE_CUSTOMER_ID,
                )
                self.assertEqual(len(result), 1)
                # The result should be LogsQueryLogEntry objects
                from datetime import datetime

                self.assertEqual(
                    result[0].TimeGenerated,
                    datetime.fromisoformat("2024-01-01T10:00:00+00:00"),
                )
                self.assertEqual(result[0].OperationId, "test-operation")
                self.assertEqual(result[0].CallerIpAddress, "192.168.1.100")
                self.assertEqual(result[0].CorrelationId, "test-correlation")

    def test_get_llm_operations_logs_no_workspace_id(self):
        """Test getting logs when the APIM instance has no workspace configured."""
        mock_provider = mock.MagicMock()
        mock_provider.identity = mock.MagicMock()
        with patch(
            "prowler.providers.azure.azure_provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            from prowler.providers.azure.services.apim.apim_service import APIM

            with patch(
                "prowler.providers.azure.services.apim.apim_service.APIM._get_instances",
                return_value={},
            ):
                apim = APIM(set_mocked_azure_provider())
                instance = mock.MagicMock(
                    log_analytics_workspace_id=None, name="test-apim"
                )
                result = apim.get_llm_operations_logs(AZURE_SUBSCRIPTION_ID, instance)
                self.assertEqual(result, [])

    def test_get_llm_operations_logs_success(self):
        """Test the successful retrieval of LLM operation logs."""
        mock_provider = mock.MagicMock()
        mock_provider.identity = mock.MagicMock()
        with patch(
            "prowler.providers.azure.azure_provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            from prowler.providers.azure.services.apim.apim_service import APIM

            with (
                patch(
                    "prowler.providers.azure.services.apim.apim_service.APIM._get_instances",
                    new=mock_apim_get_instances,
                ),
                patch(
                    "prowler.providers.azure.services.apim.apim_service.APIM.query_logs",
                    return_value=[{"log": "data"}],
                ),
                patch(
                    "prowler.providers.azure.services.apim.apim_service.APIM._get_workspace_customer_id",
                    return_value=WORKSPACE_CUSTOMER_ID,
                ),
            ):
                apim = APIM(set_mocked_azure_provider())
                instance = apim.instances[AZURE_SUBSCRIPTION_ID][0]
                result = apim.get_llm_operations_logs(AZURE_SUBSCRIPTION_ID, instance)
                self.assertEqual(result, [{"log": "data"}])
