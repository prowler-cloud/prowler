from unittest import mock
from uuid import uuid4

from prowler.providers.nhn.services.network.network_service import Network, Subnet
from tests.providers.nhn.nhn_fixtures import set_mocked_nhn_provider


class Test_network_vpc_subnet_enable_dhcp:
    def test_no_networks(self):
        # 1) Make a MagicMock for network_client
        network_client = mock.MagicMock()
        network_client.networks = []

        # 2) Patch get_global_provider() to return a mocked NHN provider
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_nhn_provider(),
            ),
            mock.patch(
                # patch the 'network_vpc_subnet_enable_dhcp.network_client' used in the check code
                "prowler.providers.nhn.services.network.network_vpc_subnet_enable_dhcp.network_vpc_subnet_enable_dhcp.network_client",
                new=network_client,
            ),
        ):
            # 3) Import the check code AFTER patching
            from prowler.providers.nhn.services.network.network_vpc_subnet_enable_dhcp.network_vpc_subnet_enable_dhcp import (
                network_vpc_subnet_enable_dhcp,
            )

            # 4) Run the check
            check = network_vpc_subnet_enable_dhcp()
            result = check.execute()

            # 5) Assertions
            assert len(result) == 0  # no networks => no findings

    def test_vpc_subnet_enable_dhcp(self):
        # Make a MagicMock for network_client
        network_client = mock.MagicMock()

        # Suppose we have 1 network with enable_dhcp=True => FAIL expected
        network_id = str(uuid4())
        network_name = "testNetwork"
        mock_network = mock.MagicMock(spec=Network)
        mock_network.id = network_id
        mock_network.name = network_name
        mock_subnet = mock.MagicMock(spec=Subnet)
        mock_subnet.name = "subnet1"
        mock_subnet.enable_dhcp = True
        mock_network.subnets = [mock_subnet]
        network_client.networks = [mock_network]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_nhn_provider(),
            ),
            mock.patch(
                "prowler.providers.nhn.services.network.network_vpc_subnet_enable_dhcp.network_vpc_subnet_enable_dhcp.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.nhn.services.network.network_vpc_subnet_enable_dhcp.network_vpc_subnet_enable_dhcp import (
                network_vpc_subnet_enable_dhcp,
            )

            check = network_vpc_subnet_enable_dhcp()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has DHCP enabled" in result[0].status_extended
            assert result[0].resource_name == network_name
            assert result[0].resource_id == network_id

    def test_vpc_subnet_unable_dhcp(self):
        # Another scenario: network with enable_dhcp=False => PASS expected
        network_client = mock.MagicMock()

        network_id = str(uuid4())
        network_name = "testNetwork"
        mock_network = mock.MagicMock(spec=Network)
        mock_network.id = network_id
        mock_network.name = network_name
        mock_subnet = mock.MagicMock(spec=Subnet)
        mock_subnet.name = "subnet1"
        mock_subnet.enable_dhcp = False
        mock_network.subnets = [mock_subnet]
        network_client.networks = [mock_network]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_nhn_provider(),
            ),
            mock.patch(
                "prowler.providers.nhn.services.network.network_vpc_subnet_enable_dhcp.network_vpc_subnet_enable_dhcp.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.nhn.services.network.network_vpc_subnet_enable_dhcp.network_vpc_subnet_enable_dhcp import (
                network_vpc_subnet_enable_dhcp,
            )

            check = network_vpc_subnet_enable_dhcp()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not have DHCP enabled" in result[0].status_extended
            assert result[0].resource_name == network_name
            assert result[0].resource_id == network_id
