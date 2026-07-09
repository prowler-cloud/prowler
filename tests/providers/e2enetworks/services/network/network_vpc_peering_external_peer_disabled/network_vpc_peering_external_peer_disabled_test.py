from unittest import mock

from prowler.providers.e2enetworks.services.network.network_service import (
    VpcTunnel,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.network.network_vpc_peering_external_peer_disabled.network_vpc_peering_external_peer_disabled.network_client"


class Test_network_vpc_peering_external_peer_disabled:
    def test_no_vpc_tunnels(self):
        client = mock.MagicMock()
        client.vpc_tunnels = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_vpc_peering_external_peer_disabled.network_vpc_peering_external_peer_disabled import (
                network_vpc_peering_external_peer_disabled,
            )

            assert network_vpc_peering_external_peer_disabled().execute() == []

    def test_network_vpc_peering_external_peer_disabled_compliant(self):
        client = mock.MagicMock()
        client.vpc_tunnels = [
            VpcTunnel(
                id="1",
                name="ok",
                location="Delhi",
                local_vpc_network_id="vpc-1",
                local_vpc_name="vpc",
                is_peer_vpc_external=False,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_vpc_peering_external_peer_disabled.network_vpc_peering_external_peer_disabled import (
                network_vpc_peering_external_peer_disabled,
            )

            findings = network_vpc_peering_external_peer_disabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_network_vpc_peering_external_peer_disabled_non_compliant(self):
        client = mock.MagicMock()
        client.vpc_tunnels = [
            VpcTunnel(
                id="2",
                name="bad",
                location="Delhi",
                local_vpc_network_id="vpc-2",
                local_vpc_name="vpc",
                is_peer_vpc_external=True,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_vpc_peering_external_peer_disabled.network_vpc_peering_external_peer_disabled import (
                network_vpc_peering_external_peer_disabled,
            )

            findings = network_vpc_peering_external_peer_disabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
