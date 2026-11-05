from unittest import mock

from prowler.providers.e2enetworks.services.node.node_service import (
    Node,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.node.node_public_ip_not_assigned.node_public_ip_not_assigned.node_client"


class Test_node_public_ip_not_assigned:
    def test_no_nodes(self):
        client = mock.MagicMock()
        client.nodes = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.node.node_public_ip_not_assigned.node_public_ip_not_assigned import (
                node_public_ip_not_assigned,
            )

            assert node_public_ip_not_assigned().execute() == []

    def test_node_public_ip_not_assigned_compliant(self):
        client = mock.MagicMock()
        client.nodes = [
            Node(
                id="1",
                name="ok",
                status="Running",
                location="Delhi",
                vm_id="1",
                has_public_ip=False,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.node.node_public_ip_not_assigned.node_public_ip_not_assigned import (
                node_public_ip_not_assigned,
            )

            findings = node_public_ip_not_assigned().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_node_public_ip_not_assigned_non_compliant(self):
        client = mock.MagicMock()
        client.nodes = [
            Node(
                id="2",
                name="bad",
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
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.node.node_public_ip_not_assigned.node_public_ip_not_assigned import (
                node_public_ip_not_assigned,
            )

            findings = node_public_ip_not_assigned().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
