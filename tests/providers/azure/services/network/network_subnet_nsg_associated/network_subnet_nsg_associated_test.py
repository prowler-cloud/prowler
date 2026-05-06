from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)

VNET_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/test-vnet"
SUBNET_ID = f"{VNET_ID}/subnets/test-subnet"
NSG_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/test-nsg"


class Test_network_subnet_nsg_associated:
    def test_no_subscriptions(self):
        network_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_subnet_nsg_associated.network_subnet_nsg_associated.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_subnet_nsg_associated.network_subnet_nsg_associated import (
                network_subnet_nsg_associated,
            )

            network_client.virtual_networks = {}

            check = network_subnet_nsg_associated()
            result = check.execute()
            assert len(result) == 0

    def test_subnet_with_nsg(self):
        network_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_subnet_nsg_associated.network_subnet_nsg_associated.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_subnet_nsg_associated.network_subnet_nsg_associated import (
                network_subnet_nsg_associated,
            )
            from prowler.providers.azure.services.network.network_service import (
                VirtualNetwork,
                VNetSubnet,
            )

            vnet = VirtualNetwork(
                id=VNET_ID,
                name="test-vnet",
                location="eastus",
                subnets=[
                    VNetSubnet(id=SUBNET_ID, name="test-subnet", nsg_id=NSG_ID)
                ],
            )
            network_client.virtual_networks = {AZURE_SUBSCRIPTION_ID: [vnet]}

            check = network_subnet_nsg_associated()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_subnet_without_nsg(self):
        network_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_subnet_nsg_associated.network_subnet_nsg_associated.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_subnet_nsg_associated.network_subnet_nsg_associated import (
                network_subnet_nsg_associated,
            )
            from prowler.providers.azure.services.network.network_service import (
                VirtualNetwork,
                VNetSubnet,
            )

            vnet = VirtualNetwork(
                id=VNET_ID,
                name="test-vnet",
                location="eastus",
                subnets=[
                    VNetSubnet(id=SUBNET_ID, name="app-subnet", nsg_id=None)
                ],
            )
            network_client.virtual_networks = {AZURE_SUBSCRIPTION_ID: [vnet]}

            check = network_subnet_nsg_associated()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_gateway_subnet_excluded(self):
        network_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_subnet_nsg_associated.network_subnet_nsg_associated.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_subnet_nsg_associated.network_subnet_nsg_associated import (
                network_subnet_nsg_associated,
            )
            from prowler.providers.azure.services.network.network_service import (
                VirtualNetwork,
                VNetSubnet,
            )

            vnet = VirtualNetwork(
                id=VNET_ID,
                name="test-vnet",
                location="eastus",
                subnets=[
                    VNetSubnet(
                        id=f"{VNET_ID}/subnets/GatewaySubnet",
                        name="GatewaySubnet",
                        nsg_id=None,
                    )
                ],
            )
            network_client.virtual_networks = {AZURE_SUBSCRIPTION_ID: [vnet]}

            check = network_subnet_nsg_associated()
            result = check.execute()
            # GatewaySubnet should be excluded
            assert len(result) == 0

    def test_mixed_subnets(self):
        network_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.network.network_subnet_nsg_associated.network_subnet_nsg_associated.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.azure.services.network.network_subnet_nsg_associated.network_subnet_nsg_associated import (
                network_subnet_nsg_associated,
            )
            from prowler.providers.azure.services.network.network_service import (
                VirtualNetwork,
                VNetSubnet,
            )

            vnet = VirtualNetwork(
                id=VNET_ID,
                name="test-vnet",
                location="eastus",
                subnets=[
                    VNetSubnet(id=f"{VNET_ID}/subnets/app", name="app", nsg_id=NSG_ID),
                    VNetSubnet(id=f"{VNET_ID}/subnets/db", name="db", nsg_id=None),
                    VNetSubnet(
                        id=f"{VNET_ID}/subnets/GatewaySubnet",
                        name="GatewaySubnet",
                        nsg_id=None,
                    ),
                ],
            )
            network_client.virtual_networks = {AZURE_SUBSCRIPTION_ID: [vnet]}

            check = network_subnet_nsg_associated()
            result = check.execute()
            # 2 results: app (PASS) + db (FAIL), GatewaySubnet excluded
            assert len(result) == 2
            statuses = {r.status for r in result}
            assert "PASS" in statuses
            assert "FAIL" in statuses
