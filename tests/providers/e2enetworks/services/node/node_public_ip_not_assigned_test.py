from unittest import mock

from prowler.providers.e2enetworks.services.node.node_service import Node
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)


class TestNodePublicIpCheck:
    def test_empty_nodes(self):
        node_client = mock.MagicMock()
        node_client.nodes = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(
                "prowler.providers.e2enetworks.services.node.node_public_ip_not_assigned.node_public_ip_not_assigned.node_client",
                new=node_client,
            ),
        ):
            from prowler.providers.e2enetworks.services.node.node_public_ip_not_assigned.node_public_ip_not_assigned import (
                node_public_ip_not_assigned,
            )

            check = node_public_ip_not_assigned()
            assert check.execute() == []

    def test_pass_and_fail(self):
        node_client = mock.MagicMock()
        node_client.nodes = [
            Node(
                id="1",
                name="private-node",
                status="Running",
                location="Delhi",
                vm_id="1",
                has_public_ip=False,
            ),
            Node(
                id="2",
                name="public-node",
                status="Running",
                location="Delhi",
                vm_id="2",
                has_public_ip=True,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(
                "prowler.providers.e2enetworks.services.node.node_public_ip_not_assigned.node_public_ip_not_assigned.node_client",
                new=node_client,
            ),
        ):
            from prowler.providers.e2enetworks.services.node.node_public_ip_not_assigned.node_public_ip_not_assigned import (
                node_public_ip_not_assigned,
            )

            check = node_public_ip_not_assigned()
            findings = check.execute()

            assert len(findings) == 2
            assert findings[0].status == "PASS"
            assert findings[1].status == "FAIL"
