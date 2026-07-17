from unittest import mock

from prowler.providers.e2enetworks.services.network.network_service import (
    ReservedIp,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.network.network_reserveip_orphaned_public_ip.network_reserveip_orphaned_public_ip.network_client"


class Test_network_reserveip_orphaned_public_ip:
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
            from prowler.providers.e2enetworks.services.network.network_reserveip_orphaned_public_ip.network_reserveip_orphaned_public_ip import (
                network_reserveip_orphaned_public_ip,
            )

            assert network_reserveip_orphaned_public_ip().execute() == []

    def test_network_reserveip_orphaned_public_ip_compliant(self):
        client = mock.MagicMock()
        client.reserved_ips = [
            ReservedIp(
                reserve_id="1",
                ip_address="1.2.3.4",
                location="Delhi",
                reserved_type="PublicIP",
                status="Attached",
                vm_id=123,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_reserveip_orphaned_public_ip.network_reserveip_orphaned_public_ip import (
                network_reserveip_orphaned_public_ip,
            )

            findings = network_reserveip_orphaned_public_ip().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_network_reserveip_orphaned_public_ip_non_compliant(self):
        client = mock.MagicMock()
        client.reserved_ips = [
            ReservedIp(
                reserve_id="2",
                ip_address="5.6.7.8",
                location="Delhi",
                reserved_type="PublicIP",
                status="Available",
                vm_id=None,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_reserveip_orphaned_public_ip.network_reserveip_orphaned_public_ip import (
                network_reserveip_orphaned_public_ip,
            )

            findings = network_reserveip_orphaned_public_ip().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
