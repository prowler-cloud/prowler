from unittest import mock

from prowler.providers.azure.services.network.network_service import NetworkWatcher
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_network_watcher_enabled:
    def test_no_network_watchers(self):
        network_client = mock.MagicMock
        network_client.resource_groups = None
        locations = []
        network_client.locations = {AZURE_SUBSCRIPTION_ID: locations}
        network_client.security_groups = {}
        network_client.network_watchers = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled import (
                network_watcher_enabled,
            )

            check = network_watcher_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_network_invalid_network_watchers(self):
        network_client = mock.MagicMock
        network_client.resource_groups = None
        locations = ["location"]
        network_client.locations = {AZURE_SUBSCRIPTION_NAME: locations}
        network_client.subscriptions = {AZURE_SUBSCRIPTION_NAME: AZURE_SUBSCRIPTION_ID}
        network_watcher_name = "Network Watcher"
        network_watcher_id = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_*"

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION_NAME: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location=None,
                    flow_logs=[],
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
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
                == f"Network Watcher is not enabled for the following locations in subscription '{AZURE_SUBSCRIPTION_NAME}': location."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_NAME
            assert result[0].resource_name == AZURE_SUBSCRIPTION_NAME
            assert result[0].resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
            assert result[0].location == "global"

    def test_network_valid_network_watchers(self):
        network_client = mock.MagicMock
        network_client.resource_groups = None
        locations = ["location"]
        network_client.locations = {AZURE_SUBSCRIPTION_NAME: locations}
        network_client.subscriptions = {AZURE_SUBSCRIPTION_NAME: AZURE_SUBSCRIPTION_ID}
        network_watcher_name = "Network Watcher"
        network_watcher_id = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_*"

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION_NAME: [
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
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
                new=network_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.azure.services.network.network_client.network_client",
                new=service_client,
            ),
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
                == f"Network Watcher {network_watcher_name} is enabled in location location in subscription '{AZURE_SUBSCRIPTION_NAME}'."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_NAME
            assert result[0].resource_name == network_watcher_name
            assert result[0].resource_id == network_watcher_id

    def test_network_watcher_enabled_returns_manual_when_resource_groups_set(self):
        network_client_mock = mock.MagicMock
        network_client_mock.subscriptions = {
            AZURE_SUBSCRIPTION_NAME: AZURE_SUBSCRIPTION_ID
        }
        network_client_mock.network_watchers = {AZURE_SUBSCRIPTION_NAME: []}
        network_client_mock.resource_groups = {AZURE_SUBSCRIPTION_NAME: ["rg"]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled.network_client",
                new=network_client_mock,
            ),
        ):
            from prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled import (
                network_watcher_enabled,
            )

            check = network_watcher_enabled()
            result = check.execute()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].subscription == AZURE_SUBSCRIPTION_NAME

    def test_network_watcher_enabled_returns_manual_when_networkwatcherrg_not_in_filter(
        self,
    ):
        network_client_mock = mock.MagicMock
        network_client_mock.subscriptions = {
            AZURE_SUBSCRIPTION_NAME: AZURE_SUBSCRIPTION_ID
        }
        network_client_mock.network_watchers = {
            AZURE_SUBSCRIPTION_NAME: [
                NetworkWatcher(
                    id=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus",
                    name="NetworkWatcher_eastus",
                    location="eastus",
                    flow_logs=[],
                )
            ]
        }
        network_client_mock.resource_groups = {AZURE_SUBSCRIPTION_NAME: ["my-app-rg"]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_service.Network",
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled.network_client",
                new=network_client_mock,
            ),
        ):
            from prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled import (
                network_watcher_enabled,
            )

            check = network_watcher_enabled()
            result = check.execute()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].subscription == AZURE_SUBSCRIPTION_NAME
        assert "--azure-resource-group" in result[0].status_extended
