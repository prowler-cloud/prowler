from unittest import mock
from uuid import uuid4

from azure.mgmt.network.models._models import FlowLog, RetentionPolicyParameters

from prowler.providers.azure.services.network.network_service import NetworkWatcher
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_network_flow_logs_captured_sent:
    def test_no_network_watchers(self):
        network_client = mock.MagicMock
        network_client.network_watchers = {}

        with mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_flow_logs_captured_sent.network_flow_logs_captured_sent import (
                network_flow_logs_captured_sent,
            )

            check = network_flow_logs_captured_sent()
            result = check.execute()
            assert len(result) == 0

    def test_network_network_watchers_no_flow_logs(self):
        network_client = mock.MagicMock
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4())

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location="location",
                    flow_logs=[],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_flow_logs_captured_sent.network_flow_logs_captured_sent import (
                network_flow_logs_captured_sent,
            )

            check = network_flow_logs_captured_sent()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION} has no flow logs"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id

    def test_network_network_watchers_flow_logs_disabled(self):
        network_client = mock.MagicMock
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4())

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location="location",
                    flow_logs=[
                        FlowLog(
                            enabled=False,
                            retention_policy=RetentionPolicyParameters(days=90),
                        )
                    ],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_flow_logs_captured_sent.network_flow_logs_captured_sent import (
                network_flow_logs_captured_sent,
            )

            check = network_flow_logs_captured_sent()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION} has flow logs disabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id

    def test_network_network_watchers_flow_logs_well_configured(self):
        network_client = mock.MagicMock
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4())

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location="location",
                    flow_logs=[
                        FlowLog(
                            enabled=True,
                            retention_policy=RetentionPolicyParameters(days=90),
                        )
                    ],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_flow_logs_captured_sent.network_flow_logs_captured_sent import (
                network_flow_logs_captured_sent,
            )

            check = network_flow_logs_captured_sent()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION} has flow logs that are captured and sent to Log Analytics workspace"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id
