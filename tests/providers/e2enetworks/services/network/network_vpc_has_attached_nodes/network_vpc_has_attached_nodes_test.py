from unittest import mock

from prowler.providers.e2enetworks.services.network.network_service import (
    Vpc,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.network.network_vpc_has_attached_nodes.network_vpc_has_attached_nodes.network_client"


class Test_network_vpc_has_attached_nodes:
    def test_no_vpcs(self):
        client = mock.MagicMock()
        client.vpcs = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_vpc_has_attached_nodes.network_vpc_has_attached_nodes import (
                network_vpc_has_attached_nodes,
            )

            assert network_vpc_has_attached_nodes().execute() == []

    def test_network_vpc_has_attached_nodes_compliant(self):
        client = mock.MagicMock()
        client.vpcs = [
            Vpc(network_id="1", name="ok", location="Delhi", vm_count=2),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_vpc_has_attached_nodes.network_vpc_has_attached_nodes import (
                network_vpc_has_attached_nodes,
            )

            findings = network_vpc_has_attached_nodes().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_network_vpc_has_attached_nodes_non_compliant(self):
        client = mock.MagicMock()
        client.vpcs = [
            Vpc(network_id="2", name="bad", location="Delhi", vm_count=0),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_vpc_has_attached_nodes.network_vpc_has_attached_nodes import (
                network_vpc_has_attached_nodes,
            )

            findings = network_vpc_has_attached_nodes().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
