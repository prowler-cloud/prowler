from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.network.network_service import (
    FlowLog,
    NetworkWatcher,
    RetentionPolicy,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
)


class Test_network_flow_log_captured_sent:
    def test_no_network_watchers(self):
        network_client = mock.MagicMock
        network_client.resource_groups = None
        network_client.network_watchers = {}

        with (
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_flow_log_captured_sent.network_flow_log_captured_sent import (
                network_flow_log_captured_sent,
            )

            check = network_flow_log_captured_sent()
            result = check.execute()
            assert len(result) == 0

    def test_network_network_watchers_no_flow_logs(self):
        network_client = mock.MagicMock
        network_client.resource_groups = None
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4())

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION_ID: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location="location",
                    flow_logs=[],
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_flow_log_captured_sent.network_flow_log_captured_sent import (
                network_flow_log_captured_sent,
            )

            check = network_flow_log_captured_sent()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION_ID} has no flow logs"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id
            assert result[0].location == "location"

    def test_network_network_watchers_flow_logs_disabled(self):
        network_client = mock.MagicMock
        network_client.resource_groups = None
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4())

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION_ID: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location="location",
                    flow_logs=[
                        FlowLog(
                            id=str(uuid4()),
                            name="disabled-flow-log",
                            enabled=False,
                            target_resource_id=None,
                            retention_policy=RetentionPolicy(days=90),
                        )
                    ],
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_flow_log_captured_sent.network_flow_log_captured_sent import (
                network_flow_log_captured_sent,
            )

            check = network_flow_log_captured_sent()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION_ID} has flow logs disabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id
            assert result[0].location == "location"

    def test_network_network_watchers_flow_logs_well_configured(self):
        network_client = mock.MagicMock
        network_client.resource_groups = None
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4())

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION_ID: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location="location",
                    flow_logs=[
                        FlowLog(
                            id=str(uuid4()),
                            name="workspace-disabled",
                            enabled=True,
                            target_resource_id="/subscriptions/test-sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/test-vnet",
                            retention_policy=RetentionPolicy(days=90),
                        )
                    ],
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_flow_log_captured_sent.network_flow_log_captured_sent import (
                network_flow_log_captured_sent,
            )

            check = network_flow_log_captured_sent()
            result = check.execute()
            assert len(result) == 1
            assert result[0].location == "location"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION_ID} has enabled flow logs that are not configured to send traffic analytics to a Log Analytics workspace"
            )

    def test_network_network_watchers_traffic_analytics_without_workspace(self):
        network_client = mock.MagicMock
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4())

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION_ID: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location="location",
                    flow_logs=[
                        FlowLog(
                            id=str(uuid4()),
                            name="ta-without-workspace",
                            enabled=True,
                            target_resource_id="/subscriptions/test-sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/test-vnet",
                            retention_policy=RetentionPolicy(days=90),
                            traffic_analytics_enabled=True,
                            workspace_resource_id=None,
                        )
                    ],
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_flow_log_captured_sent.network_flow_log_captured_sent import (
                network_flow_log_captured_sent,
            )

            check = network_flow_log_captured_sent()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION_ID} has enabled flow logs that are not configured to send traffic analytics to a Log Analytics workspace"
            )

    def test_network_network_watchers_mixed_flow_logs_fails(self):
        network_client = mock.MagicMock
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4())

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION_ID: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location="location",
                    flow_logs=[
                        FlowLog(
                            id=str(uuid4()),
                            name="vnet-flow-log-workspace-backed",
                            enabled=True,
                            target_resource_id="/subscriptions/test-sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/test-vnet",
                            retention_policy=RetentionPolicy(days=90),
                            traffic_analytics_enabled=True,
                            workspace_resource_id="/subscriptions/test-sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/test-law",
                        ),
                        FlowLog(
                            id=str(uuid4()),
                            name="nsg-flow-log-storage-only",
                            enabled=True,
                            target_resource_id="/subscriptions/test-sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg",
                            retention_policy=RetentionPolicy(days=90),
                            traffic_analytics_enabled=False,
                            workspace_resource_id=None,
                        ),
                    ],
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_flow_log_captured_sent.network_flow_log_captured_sent import (
                network_flow_log_captured_sent,
            )

            check = network_flow_log_captured_sent()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION_ID} has enabled flow logs that are not configured to send traffic analytics to a Log Analytics workspace"
            )

    def test_network_network_watchers_vnet_flow_logs_well_configured(self):
        network_client = mock.MagicMock
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4())

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION_ID: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location="location",
                    flow_logs=[
                        FlowLog(
                            id=str(uuid4()),
                            name="vnet-flow-log",
                            enabled=True,
                            target_resource_id="/subscriptions/test-sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/test-vnet",
                            retention_policy=RetentionPolicy(days=90),
                            traffic_analytics_enabled=True,
                            workspace_resource_id="/subscriptions/test-sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/test-law",
                        )
                    ],
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_flow_log_captured_sent.network_flow_log_captured_sent import (
                network_flow_log_captured_sent,
            )

            check = network_flow_log_captured_sent()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].location == "location"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION_ID} has flow logs that are captured and sent to Log Analytics workspace"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id

    def test_network_flow_log_captured_sent_returns_manual_when_resource_groups_set(
        self,
    ):
        network_client_mock = mock.MagicMock
        network_client_mock.subscriptions = {
            AZURE_SUBSCRIPTION_NAME: AZURE_SUBSCRIPTION_ID
        }
        network_client_mock.network_watchers = {AZURE_SUBSCRIPTION_NAME: []}
        network_client_mock.resource_groups = {AZURE_SUBSCRIPTION_NAME: ["rg"]}

        with (
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client_mock,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
        ):
            from importlib import reload

            import prowler.providers.azure.services.network.network_flow_log_captured_sent.network_flow_log_captured_sent as mod

            reload(mod)
            check = mod.network_flow_log_captured_sent()
            result = check.execute()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].subscription == AZURE_SUBSCRIPTION_NAME
