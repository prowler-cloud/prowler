from unittest import mock
from uuid import uuid4

from azure.mgmt.network.models._models import FlowLog, RetentionPolicyParameters

from prowler.providers.azure.services.network.network_service import NetworkWatcher

AZURE_SUBSCRIPTION = str(uuid4())


class Test_network_flow_log_more_than_90_days:
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
            from prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days import (
                network_flow_log_more_than_90_days,
            )

            check = network_flow_log_more_than_90_days()
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
            from prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days import (
                network_flow_log_more_than_90_days,
            )

            check = network_flow_log_more_than_90_days()
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
            from prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days import (
                network_flow_log_more_than_90_days,
            )

            check = network_flow_log_more_than_90_days()
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

    def test_network_network_watchers_flow_logs_retention_days_80(self):
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
                            retention_policy=RetentionPolicyParameters(days=80),
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
            from prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days import (
                network_flow_log_more_than_90_days,
            )

            check = network_flow_log_more_than_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION} flow logs retention policy is less than 90 days"
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
            from prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days import (
                network_flow_log_more_than_90_days,
            )

            check = network_flow_log_more_than_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Network Watcher {network_watcher_name} from subscription {AZURE_SUBSCRIPTION} has flow logs enabled for more than 90 days"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id
