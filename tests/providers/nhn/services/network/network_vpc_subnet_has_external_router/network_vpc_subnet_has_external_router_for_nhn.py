from unittest import mock
from uuid import uuid4

from prowler.providers.nhn.services.network.network_service import Network, Subnet
from tests.providers.nhn.nhn_fixtures import set_mocked_nhn_provider


class Test_network_vpc_subnet_has_external_router:
    def test_no_networks(self):
        network_client = mock.MagicMock()
        network_client.networks = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_nhn_provider(),
            ),
            mock.patch(
                "prowler.providers.nhn.services.network.network_vpc_subnet_has_external_router.network_vpc_subnet_has_external_router.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.nhn.services.network.network_vpc_subnet_has_external_router.network_vpc_subnet_has_external_router import (
                network_vpc_subnet_has_external_router,
            )

            check = network_vpc_subnet_has_external_router()
            result = check.execute()

            assert len(result) == 0

    def test_vpc_subnet_has_external_router(self):
        network_client = mock.MagicMock()

        network_id = str(uuid4())
        network_name = "testNetwork"
        mock_network = mock.MagicMock(spec=Network)
        mock_network.id = network_id
        mock_network.name = network_name
        mock_subnet = mock.MagicMock(spec=Subnet)
        mock_subnet.name = "subnet1"
        mock_subnet.external_router = True
        mock_network.subnets = [mock_subnet]
        network_client.networks = [mock_network]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_nhn_provider(),
            ),
            mock.patch(
                "prowler.providers.nhn.services.network.network_vpc_subnet_has_external_router.network_vpc_subnet_has_external_router.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.nhn.services.network.network_vpc_subnet_has_external_router.network_vpc_subnet_has_external_router import (
                network_vpc_subnet_has_external_router,
            )

            check = network_vpc_subnet_has_external_router()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has external router" in result[0].status_extended
            assert result[0].resource_id == network_id
            assert result[0].resource_name == network_name

    def test_vpc_subnet_no_external_router(self):
        network_client = mock.MagicMock()

        network_id = str(uuid4())
        network_name = "testNetwork"
        mock_network = mock.MagicMock(spec=Network)
        mock_network.id = network_id
        mock_network.name = network_name
        mock_subnet = mock.MagicMock(spec=Subnet)
        mock_subnet.name = "subnet1"
        mock_subnet.external_router = False
        mock_network.subnets = [mock_subnet]
        network_client.networks = [mock_network]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_nhn_provider(),
            ),
            mock.patch(
                "prowler.providers.nhn.services.network.network_vpc_subnet_has_external_router.network_vpc_subnet_has_external_router.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.nhn.services.network.network_vpc_subnet_has_external_router.network_vpc_subnet_has_external_router import (
                network_vpc_subnet_has_external_router,
            )

            check = network_vpc_subnet_has_external_router()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no external router" in result[0].status_extended
            assert result[0].resource_id == network_id
            assert result[0].resource_name == network_name
