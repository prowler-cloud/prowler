from unittest import mock

from prowler.providers.azure.services.network.network_service import NetworkWatcher
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    AZURE_SUBSCRIPTION_ID,
)


class Test_network_watcher_enabled:
    def test_no_network_watchers(self):
        network_client = mock.MagicMock
        locations = []
        network_client.locations = {AZURE_SUBSCRIPTION: locations}
        network_client.security_groups = {}
        network_client.network_watchers = {}

        with mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled import (
                network_watcher_enabled,
            )

            check = network_watcher_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_network_invalid_network_watchers(self):
        network_client = mock.MagicMock
        locations = ["location"]
        network_client.locations = {AZURE_SUBSCRIPTION: locations}
        network_client.subscriptions = {AZURE_SUBSCRIPTION: AZURE_SUBSCRIPTION_ID}
        network_watcher_name = "Network Watcher"
        network_watcher_id = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_*"

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location=None,
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
            from prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled import (
                network_watcher_enabled,
            )

            check = network_watcher_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Network Watcher is not enabled for the following locations in subscription '{AZURE_SUBSCRIPTION}': location."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id
            assert result[0].location == "Global"

    def test_network_valid_network_watchers(self):
        network_client = mock.MagicMock
        locations = ["location"]
        network_client.locations = {AZURE_SUBSCRIPTION: locations}
        network_client.subscriptions = {AZURE_SUBSCRIPTION: AZURE_SUBSCRIPTION_ID}
        network_watcher_name = "Network Watcher"
        network_watcher_id = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_*"

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
            from prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled import (
                network_watcher_enabled,
            )

            check = network_watcher_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Network Watcher is enabled for all locations in subscription '{AZURE_SUBSCRIPTION}'."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id
            assert result[0].location == "Global"
