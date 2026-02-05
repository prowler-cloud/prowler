"""Tests for network_subnet_dhcp_disabled check."""

from unittest import mock

from prowler.providers.openstack.services.network.network_service import Subnet
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_network_subnet_dhcp_disabled:
    def test_subnet_dhcp_enabled(self):
        network_client = mock.MagicMock()
        network_client.subnets = [
            Subnet(
                id="subnet-1",
                name="app-subnet",
                network_id="net-1",
                ip_version=4,
                cidr="192.168.1.0/24",
                gateway_ip="192.168.1.1",
                enable_dhcp=True,
                dns_nameservers=["8.8.8.8"],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_subnet_dhcp_disabled.network_subnet_dhcp_disabled.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_subnet_dhcp_disabled.network_subnet_dhcp_disabled import (
                network_subnet_dhcp_disabled,
            )

            check = network_subnet_dhcp_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_subnet_dhcp_disabled(self):
        network_client = mock.MagicMock()
        network_client.subnets = [
            Subnet(
                id="subnet-2",
                name="static-subnet",
                network_id="net-1",
                ip_version=4,
                cidr="10.0.1.0/24",
                gateway_ip="10.0.1.1",
                enable_dhcp=False,
                dns_nameservers=[],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_subnet_dhcp_disabled.network_subnet_dhcp_disabled.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_subnet_dhcp_disabled.network_subnet_dhcp_disabled import (
                network_subnet_dhcp_disabled,
            )

            check = network_subnet_dhcp_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has DHCP disabled" in result[0].status_extended
