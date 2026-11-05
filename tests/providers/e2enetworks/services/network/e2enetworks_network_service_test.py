from unittest.mock import MagicMock, patch

from prowler.providers.e2enetworks.services.network.network_service import Network, Vpc


class TestNetworkService:
    @patch(
        "prowler.providers.e2enetworks.services.network.network_service.E2eNetworksService.__init__"
    )
    def test_fetch_vpcs_and_tunnels(self, mock_super_init):
        mock_super_init.return_value = None

        provider = MagicMock()
        provider.session.locations = ["Delhi"]
        service = Network.__new__(Network)
        service.provider = provider
        service.client = MagicMock()
        service.vpcs = []
        service.reserved_ips = []
        service.vpc_tunnels = []

        service.client.paginate.return_value = [
            {
                "network_id": 100,
                "name": "VPC-100",
                "is_active": True,
                "state": "Active",
                "ipv4_cidr": "10.0.0.0/23",
                "vm_count": 2,
                "gateway_node": {"node_id": 1, "ip_address_public": "1.2.3.4"},
            }
        ]
        service.client.get_data.side_effect = [
            [
                {
                    "reserve_id": 10,
                    "ip_address": "164.52.1.1",
                    "status": "Attached",
                    "reserved_type": "FloatingIP",
                    "vm_id": 55,
                    "floating_ip_attached_nodes": [{"id": 1}],
                }
            ],
            [
                {
                    "id": 5,
                    "name": "peer-tunnel",
                    "status": "ACTIVE",
                    "is_peer_vpc_external": True,
                }
            ],
        ]

        service._fetch_vpcs()
        service._fetch_reserved_ips()
        service._fetch_vpc_tunnels()

        assert len(service.vpcs) == 1
        assert service.vpcs[0].vm_count == 2
        assert len(service.reserved_ips) == 1
        assert service.reserved_ips[0].floating_ip_attached_nodes_count == 1
        assert len(service.vpc_tunnels) == 1
        assert service.vpc_tunnels[0].is_peer_vpc_external is True


class TestVpcModel:
    def test_resource_properties(self):
        vpc = Vpc(
            network_id="100",
            name="VPC-100",
            location="Delhi",
        )
        assert vpc.resource_id == "100"
        assert vpc.resource_name == "VPC-100"
