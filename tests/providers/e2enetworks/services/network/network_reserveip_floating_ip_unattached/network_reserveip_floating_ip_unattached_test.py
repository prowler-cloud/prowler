from unittest import mock

from prowler.providers.e2enetworks.services.network.network_service import (
    ReservedIp,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.network.network_reserveip_floating_ip_unattached.network_reserveip_floating_ip_unattached.network_client"


class Test_network_reserveip_floating_ip_unattached:
    def test_no_reserved_ips(self):
        client = mock.MagicMock()
        client.reserved_ips = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_reserveip_floating_ip_unattached.network_reserveip_floating_ip_unattached import (
                network_reserveip_floating_ip_unattached,
            )

            assert network_reserveip_floating_ip_unattached().execute() == []

    def test_network_reserveip_floating_ip_unattached_compliant(self):
        client = mock.MagicMock()
        client.reserved_ips = [
            ReservedIp(
                reserve_id="1",
                ip_address="1.2.3.4",
                location="Delhi",
                reserved_type="FloatingIP",
                status="Attached",
                floating_ip_attached_nodes_count=1,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_reserveip_floating_ip_unattached.network_reserveip_floating_ip_unattached import (
                network_reserveip_floating_ip_unattached,
            )

            findings = network_reserveip_floating_ip_unattached().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_network_reserveip_floating_ip_unattached_non_compliant(self):
        client = mock.MagicMock()
        client.reserved_ips = [
            ReservedIp(
                reserve_id="2",
                ip_address="5.6.7.8",
                location="Delhi",
                reserved_type="FloatingIP",
                status="Available",
                floating_ip_attached_nodes_count=0,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_reserveip_floating_ip_unattached.network_reserveip_floating_ip_unattached import (
                network_reserveip_floating_ip_unattached,
            )

            findings = network_reserveip_floating_ip_unattached().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
