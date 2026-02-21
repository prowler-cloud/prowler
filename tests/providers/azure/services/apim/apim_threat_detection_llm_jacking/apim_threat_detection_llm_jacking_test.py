from datetime import datetime
from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


# Create a mock LogsQueryLogEntry class for testing
class MockLogsQueryLogEntry:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def mock_get_llm_operations_logs(subscription, instance, minutes):
    """Mock LLM operations logs for testing - returns 2 operations"""
    return [
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:00:00+00:00"),
            operation_id="ChatCompletions_Create",
            caller_ip_address="192.168.1.100",
            correlation_id="test-correlation-id-1",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:01:00+00:00"),
            operation_id="ImageGenerations_Create",
            caller_ip_address="192.168.1.100",
            correlation_id="test-correlation-id-2",
        ),
    ]


def mock_get_llm_operations_logs_6_operations(subscription, instance, minutes):
    """Mock LLM operations logs for testing - returns 6 operations"""
    return [
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:00:00+00:00"),
            operation_id="ChatCompletions_Create",
            caller_ip_address="192.168.1.100",
            correlation_id="test-correlation-id-1",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:01:00+00:00"),
            operation_id="ImageGenerations_Create",
            caller_ip_address="192.168.1.100",
            correlation_id="test-correlation-id-2",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:02:00+00:00"),
            operation_id="Completions_Create",
            caller_ip_address="192.168.1.100",
            correlation_id="test-correlation-id-3",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:03:00+00:00"),
            operation_id="Embeddings_Create",
            caller_ip_address="192.168.1.100",
            correlation_id="test-correlation-id-4",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:04:00+00:00"),
            operation_id="FineTuning_Jobs_Create",
            caller_ip_address="192.168.1.100",
            correlation_id="test-correlation-id-5",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:05:00+00:00"),
            operation_id="Models_List",
            caller_ip_address="192.168.1.100",
            correlation_id="test-correlation-id-6",
        ),
    ]


def mock_get_llm_operations_logs_2_operations(subscription, instance, minutes):
    """Mock LLM operations logs for testing - returns 2 operations"""
    return [
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:00:00+00:00"),
            operation_id="ChatCompletions_Create",
            caller_ip_address="192.168.1.100",
            correlation_id="test-correlation-id-1",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:01:00+00:00"),
            operation_id="ImageGenerations_Create",
            caller_ip_address="192.168.1.100",
            correlation_id="test-correlation-id-2",
        ),
    ]


def mock_get_llm_operations_logs_attacker(subscription, instance, minutes):
    """Mock LLM operations logs showing potential attack"""
    return [
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:00:00+00:00"),
            operation_id="ChatCompletions_Create",
            caller_ip_address="10.0.0.50",
            correlation_id="test-correlation-id-1",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:01:00+00:00"),
            operation_id="ImageGenerations_Create",
            caller_ip_address="10.0.0.50",
            correlation_id="test-correlation-id-2",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:02:00+00:00"),
            operation_id="Completions_Create",
            caller_ip_address="10.0.0.50",
            correlation_id="test-correlation-id-3",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:03:00+00:00"),
            operation_id="Embeddings_Create",
            caller_ip_address="10.0.0.50",
            correlation_id="test-correlation-id-4",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:04:00+00:00"),
            operation_id="FineTuning_Jobs_Create",
            caller_ip_address="10.0.0.50",
            correlation_id="test-correlation-id-5",
        ),
        MockLogsQueryLogEntry(
            time_generated=datetime.fromisoformat("2024-01-01T10:05:00+00:00"),
            operation_id="Models_List",
            caller_ip_address="10.0.0.50",
            correlation_id="test-correlation-id-6",
        ),
    ]


def mock_get_llm_operations_logs_no_workspace(subscription, instance, minutes):
    """Mock LLM operations logs for instance without workspace"""
    return []


class Test_apim_threat_detection_llm_jacking:
    def test_no_apim_instances(self):
        """Test when there are no APIM instances"""
        apim_client = mock.MagicMock()
        apim_client.instances = {}
        apim_client.audit_config = {
            "apim_threat_detection_llm_jacking_threshold": 0.1,
            "apim_threat_detection_llm_jacking_minutes": 1440,
            "apim_threat_detection_llm_jacking_actions": [
                "ChatCompletions_Create",
                "ImageGenerations_Create",
            ],
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking.apim_client",
                new=apim_client,
            ),
        ):
            from prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking import (
                apim_threat_detection_llm_jacking,
            )

            check = apim_threat_detection_llm_jacking()
            result = check.execute()

            assert len(result) == 0

    def test_no_potential_llm_jacking(self):
        """Test when no potential LLM jacking is detected"""
        apim_client = mock.MagicMock()
        apim_client.instances = {
            AZURE_SUBSCRIPTION_ID: [
                mock.MagicMock(
                    id="/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.ApiManagement/service/test-apim",
                    name="test-apim",
                    log_analytics_workspace_id="/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.OperationalInsights/workspaces/test-workspace",
                )
            ]
        }
        apim_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_ID}
        apim_client.audit_config = {
            "apim_threat_detection_llm_jacking_threshold": 0.9,
            "apim_threat_detection_llm_jacking_minutes": 1440,
            "apim_threat_detection_llm_jacking_actions": [
                "ChatCompletions_Create",
                "ImageGenerations_Create",
                "Completions_Create",
                "Embeddings_Create",
                "FineTuning_Jobs_Create",
                "Models_List",
                "Deployments_List",
                "Deployments_Get",
                "Deployments_Create",
                "Deployments_Delete",
                "Messages_Create",
                "Claude_Create",
                "GenerateContent",
                "GenerateText",
                "GenerateImage",
                "Llama_Create",
                "CodeLlama_Create",
                "Gemini_Generate",
                "Claude_Generate",
                "Llama_Generate",
            ],
        }
        apim_client.get_llm_operations_logs = mock_get_llm_operations_logs_6_operations

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking.apim_client",
                new=apim_client,
            ),
        ):
            from prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking import (
                apim_threat_detection_llm_jacking,
            )

            check = apim_threat_detection_llm_jacking()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "No potential LLM Jacking attacks detected" in result[0].status_extended
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_potential_llm_jacking_detected(self):
        """Test when potential LLM jacking is detected"""
        apim_client = mock.MagicMock()
        apim_client.instances = {
            AZURE_SUBSCRIPTION_ID: [
                mock.MagicMock(
                    id="/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.ApiManagement/service/test-apim",
                    name="test-apim",
                    log_analytics_workspace_id="/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.OperationalInsights/workspaces/test-workspace",
                )
            ]
        }
        apim_client.audit_config = {
            "apim_threat_detection_llm_jacking_threshold": 0.1,
            "apim_threat_detection_llm_jacking_minutes": 1440,
            "apim_threat_detection_llm_jacking_actions": [
                "ChatCompletions_Create",
                "ImageGenerations_Create",
                "Completions_Create",
                "Embeddings_Create",
                "FineTuning_Jobs_Create",
                "Models_List",
            ],
        }
        apim_client.get_llm_operations_logs = mock_get_llm_operations_logs_attacker

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking.apim_client",
                new=apim_client,
            ),
        ):
            from prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking import (
                apim_threat_detection_llm_jacking,
            )

            check = apim_threat_detection_llm_jacking()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "Potential LLM Jacking attack detected from IP address 10.0.0.50"
                in result[0].status_extended
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource["name"] == "10.0.0.50"
            assert result[0].resource["id"] == "10.0.0.50"

    def test_higher_threshold_no_detection(self):
        """Test when threshold is higher and no attack is detected"""
        apim_client = mock.MagicMock()
        apim_client.instances = {
            AZURE_SUBSCRIPTION_ID: [
                mock.MagicMock(
                    id="/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.ApiManagement/service/test-apim",
                    name="test-apim",
                    log_analytics_workspace_id="/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.OperationalInsights/workspaces/test-workspace",
                )
            ]
        }
        apim_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_ID}
        apim_client.audit_config = {
            "apim_threat_detection_llm_jacking_threshold": 0.9,
            "apim_threat_detection_llm_jacking_minutes": 1440,
            "apim_threat_detection_llm_jacking_actions": [
                "ChatCompletions_Create",
                "ImageGenerations_Create",
                "Completions_Create",
                "Embeddings_Create",
                "FineTuning_Jobs_Create",
                "Models_List",
                "Deployments_List",
                "Deployments_Get",
                "Deployments_Create",
                "Deployments_Delete",
                "Messages_Create",
                "Claude_Create",
                "GenerateContent",
                "GenerateText",
                "GenerateImage",
                "Llama_Create",
                "CodeLlama_Create",
                "Gemini_Generate",
                "Claude_Generate",
                "Llama_Generate",
            ],
        }
        apim_client.get_llm_operations_logs = mock_get_llm_operations_logs_6_operations

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking.apim_client",
                new=apim_client,
            ),
        ):
            from prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking import (
                apim_threat_detection_llm_jacking,
            )

            check = apim_threat_detection_llm_jacking()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "No potential LLM Jacking attacks detected" in result[0].status_extended
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_instance_without_workspace(self):
        """Test when APIM instance has no Log Analytics workspace configured"""
        apim_client = mock.MagicMock()
        apim_client.instances = {
            AZURE_SUBSCRIPTION_ID: [
                mock.MagicMock(
                    id="/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.ApiManagement/service/test-apim",
                    name="test-apim",
                    log_analytics_workspace_id=None,
                )
            ]
        }
        apim_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_ID}
        apim_client.audit_config = {
            "apim_threat_detection_llm_jacking_threshold": 0.9,
            "apim_threat_detection_llm_jacking_minutes": 1440,
            "apim_threat_detection_llm_jacking_actions": [
                "ChatCompletions_Create",
                "ImageGenerations_Create",
                "Completions_Create",
                "Embeddings_Create",
                "FineTuning_Jobs_Create",
                "Models_List",
                "Deployments_List",
                "Deployments_Get",
                "Deployments_Create",
                "Deployments_Delete",
                "Messages_Create",
                "Claude_Create",
                "GenerateContent",
                "GenerateText",
                "GenerateImage",
                "Llama_Create",
                "CodeLlama_Create",
                "Gemini_Generate",
                "Claude_Generate",
                "Llama_Generate",
            ],
        }
        apim_client.get_llm_operations_logs = mock_get_llm_operations_logs_2_operations

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking.apim_client",
                new=apim_client,
            ),
        ):
            from prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking import (
                apim_threat_detection_llm_jacking,
            )

            check = apim_threat_detection_llm_jacking()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "No potential LLM Jacking attacks detected" in result[0].status_extended
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_multiple_subscriptions(self):
        """Test with multiple subscriptions"""
        apim_client = mock.MagicMock()
        apim_client.instances = {
            AZURE_SUBSCRIPTION_ID: [
                mock.MagicMock(
                    id="/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.ApiManagement/service/test-apim",
                    name="test-apim",
                    log_analytics_workspace_id="/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.OperationalInsights/workspaces/test-workspace",
                )
            ],
            "another-subscription": [
                mock.MagicMock(
                    id="/subscriptions/another-sub/resourceGroups/test-rg/providers/Microsoft.ApiManagement/service/another-apim",
                    name="another-apim",
                    log_analytics_workspace_id="/subscriptions/another-sub/resourceGroups/test-rg/providers/Microsoft.OperationalInsights/workspaces/another-workspace",
                )
            ],
        }
        apim_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_ID,
            "another-subscription": "another-subscription-id",
        }
        apim_client.audit_config = {
            "apim_threat_detection_llm_jacking_threshold": 0.9,
            "apim_threat_detection_llm_jacking_minutes": 1440,
            "apim_threat_detection_llm_jacking_actions": [
                "ChatCompletions_Create",
                "ImageGenerations_Create",
                "Completions_Create",
                "Embeddings_Create",
                "FineTuning_Jobs_Create",
                "Models_List",
                "Deployments_List",
                "Deployments_Get",
                "Deployments_Create",
                "Deployments_Delete",
                "Messages_Create",
                "Claude_Create",
                "GenerateContent",
                "GenerateText",
                "GenerateImage",
                "Llama_Create",
                "CodeLlama_Create",
                "Gemini_Generate",
                "Claude_Generate",
                "Llama_Generate",
            ],
        }
        apim_client.get_llm_operations_logs = mock_get_llm_operations_logs_2_operations

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking.apim_client",
                new=apim_client,
            ),
        ):
            from prowler.providers.azure.services.apim.apim_threat_detection_llm_jacking.apim_threat_detection_llm_jacking import (
                apim_threat_detection_llm_jacking,
            )

            check = apim_threat_detection_llm_jacking()
            result = check.execute()

            assert len(result) == 2
            # Both subscriptions should have PASS results
            for report in result:
                assert report.status == "PASS"
                assert (
                    "No potential LLM Jacking attacks detected"
                    in report.status_extended
                )
