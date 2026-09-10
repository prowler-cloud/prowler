from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.e2enetworks.services.node.node_service import Node, Nodes


class TestNodesService:
    @patch(
        "prowler.providers.e2enetworks.services.node.node_service.E2eNetworksService.__init__"
    )
    def test_fetch_nodes_enriches_detail(self, mock_super_init):
        mock_super_init.return_value = None

        provider = MagicMock()
        provider.session.locations = ["Delhi"]
        service = Nodes.__new__(Nodes)
        service.provider = provider
        service.client = MagicMock()
        service.nodes = []

        service.client.get_data.side_effect = [
            [
                {
                    "id": 101,
                    "name": "node-1",
                    "status": "Running",
                    "public_ip_address": "1.2.3.4",
                    "is_accidental_protection": True,
                    "isEncryptionEnabled": True,
                    "is_locked": False,
                    "rescue_mode_status": "Disabled",
                }
            ],
            {
                "vm_id": 555,
                "is_node_compliance": True,
                "is_vpc_attached": True,
            },
        ]

        service._fetch_nodes()

        assert len(service.nodes) == 1
        node = service.nodes[0]
        assert node.id == "101"
        assert node.vm_id == "555"
        assert node.has_public_ip is True
        assert node.is_node_compliance is True
        assert node.is_vpc_attached is True


class TestNodeCheckLogic:
    def test_node_public_ip_detection(self):
        public_node = Node(
            id="1",
            name="public",
            status="Running",
            location="Delhi",
            vm_id="1",
            has_public_ip=True,
        )
        private_node = Node(
            id="2",
            name="private",
            status="Running",
            location="Delhi",
            vm_id="2",
            has_public_ip=False,
        )

        assert public_node.has_public_ip is True
        assert private_node.has_public_ip is False


class TestHasPublicIp:
    @pytest.mark.parametrize(
        "public_ip_address,expected",
        [
            (None, False),
            ("", False),
            ("[]", False),
            ("null", False),
            ("None", False),
            ("1.2.3.4", True),
            ("  10.0.0.1  ", True),
        ],
    )
    def test_has_public_ip_normalization(self, public_ip_address, expected):
        from prowler.providers.e2enetworks.services.node.node_service import (
            _has_public_ip,
        )

        assert _has_public_ip(public_ip_address) is expected
