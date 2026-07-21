from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)

VNET_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/test-vnet"


class Test_network_vnet_ddos_protection_enabled:
    def test_no_subscriptions(self):
        network_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_vnet_ddos_protection_enabled.network_vnet_ddos_protection_enabled.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_vnet_ddos_protection_enabled.network_vnet_ddos_protection_enabled import (
                network_vnet_ddos_protection_enabled,
            )

            network_client.virtual_networks = {}

            check = network_vnet_ddos_protection_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_ddos_enabled(self):
        network_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_vnet_ddos_protection_enabled.network_vnet_ddos_protection_enabled.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_vnet_ddos_protection_enabled.network_vnet_ddos_protection_enabled import (
                network_vnet_ddos_protection_enabled,
            )
            from prowler.providers.azure.services.network.network_service import (
                VirtualNetwork,
            )

            vnet = VirtualNetwork(
                id=VNET_ID,
                name="test-vnet",
                location="eastus",
                enable_ddos_protection=True,
            )
            network_client.virtual_networks = {AZURE_SUBSCRIPTION_ID: [vnet]}

            check = network_vnet_ddos_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_ddos_disabled(self):
        network_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_vnet_ddos_protection_enabled.network_vnet_ddos_protection_enabled.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_vnet_ddos_protection_enabled.network_vnet_ddos_protection_enabled import (
                network_vnet_ddos_protection_enabled,
            )
            from prowler.providers.azure.services.network.network_service import (
                VirtualNetwork,
            )

            vnet = VirtualNetwork(
                id=VNET_ID,
                name="test-vnet",
                location="eastus",
                enable_ddos_protection=False,
            )
            network_client.virtual_networks = {AZURE_SUBSCRIPTION_ID: [vnet]}

            check = network_vnet_ddos_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
