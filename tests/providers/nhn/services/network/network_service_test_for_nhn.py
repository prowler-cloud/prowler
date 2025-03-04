from unittest.mock import MagicMock, patch

from prowler.providers.nhn.services.network.network_service import NHNNetworkService
from tests.providers.nhn.nhn_fixtures import set_mocked_nhn_provider


class TestNHNNetworkService:
    @patch("prowler.providers.nhn.services.network.network_service.logger")
    def test_network_service_basic(self, mock_logger):
        """
        Test that NHNNetworkService correctly calls _list_vpcs(),
        _get_vpc_detail() for each VPC, and populates self.networks and self.subnets.
        """
        # create a mocked NHN Provider
        provider = set_mocked_nhn_provider(
            username="testUser",
            password="testPass",
            tenant_id="tenant123",
        )

        # define mocked responses for VPCs and Subnets
        mocked_response_vpcs = MagicMock()
        mocked_response_vpcs.status_code = 200
        mocked_response_vpcs.json.return_value = {
            "vpcs": [
                {"id": "vpc1", "name": "myvpc1"},
                {"id": "vpc2", "name": "myvpc2"},
            ]
        }

        mocked_response_vpc1 = MagicMock()
        mocked_response_vpc1.status_code = 200
        mocked_response_vpc1.json.return_value = {
            "vpc": {
                "routingtables": [],
                "subnets": [
                    {"name": "subnet1", "router:external": True, "enable_dhcp": False},
                ],
            }
        }

        mocked_response_vpc2 = MagicMock()
        mocked_response_vpc2.status_code = 200
        mocked_response_vpc2.json.return_value = {
            "vpc": {
                "routingtables": [{"id": "rt1"}],
                "subnets": [
                    {"name": "subnet2", "router:external": False, "enable_dhcp": True},
                ],
            }
        }

        def get_side_effect(url, timeout=10):
            print(f"Called with timeout={timeout}")
            if (
                "/v2.0/vpcs" in url
                and not url.endswith("vpc1")
                and not url.endswith("vpc2")
            ):
                return mocked_response_vpcs
            elif url.endswith("vpc1"):
                return mocked_response_vpc1
            elif url.endswith("vpc2"):
                return mocked_response_vpc2
            else:
                mock_404 = MagicMock()
                mock_404.status_code = 404
                mock_404.text = "Not Found"
                return mock_404

        provider.session.get.side_effect = get_side_effect

        # create NHNNetworkService, which internally calls _get_networks() and _get_subnets()
        network_service = NHNNetworkService(provider)

        assert len(network_service.networks) == 2

        # first network
        net1 = network_service.networks[0]
        assert net1.id == "vpc1"
        assert net1.name == "myvpc1"
        assert net1.empty_routingtables is True
        assert len(net1.subnets) == 1
        assert net1.subnets[0].name == "subnet1"
        assert net1.subnets[0].external_router is True
        assert net1.subnets[0].enable_dhcp is False

        # second network
        net2 = network_service.networks[1]
        assert net2.id == "vpc2"
        assert net2.name == "myvpc2"
        assert net2.empty_routingtables is False  # Assuming there's a routing table
        assert len(net2.subnets) == 1
        assert net2.subnets[0].name == "subnet2"
        assert net2.subnets[0].external_router is False
        assert net2.subnets[0].enable_dhcp is True

        mock_logger.error.assert_not_called()
