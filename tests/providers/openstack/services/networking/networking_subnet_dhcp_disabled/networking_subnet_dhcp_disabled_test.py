"""Tests for network_subnet_dhcp_disabled check."""

from unittest import mock

from prowler.providers.openstack.services.networking.networking_service import Subnet
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_networking_subnet_dhcp_disabled:
    """Test suite for network_subnet_dhcp_disabled check."""

    def test_no_subnets(self):
        """Test when no subnets exist."""
        network_client = mock.MagicMock()
        network_client.subnets = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.networking.networking_subnet_dhcp_disabled.networking_subnet_dhcp_disabled.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_subnet_dhcp_disabled.networking_subnet_dhcp_disabled import (
                networking_subnet_dhcp_disabled,
            )

            check = networking_subnet_dhcp_disabled()
            result = check.execute()

            assert len(result) == 0

    def test_subnet_dhcp_enabled(self):
        """Test subnet with DHCP enabled (PASS)."""
        network_client = mock.MagicMock()
        network_client.subnets = [
            Subnet(
                id="subnet-1",
                name="production-subnet",
                network_id="net-1",
                ip_version=4,
                cidr="192.168.1.0/24",
                gateway_ip="192.168.1.1",
                enable_dhcp=True,
                dns_nameservers=["8.8.8.8", "8.8.4.4"],
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
                "prowler.providers.openstack.services.networking.networking_subnet_dhcp_disabled.networking_subnet_dhcp_disabled.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_subnet_dhcp_disabled.networking_subnet_dhcp_disabled import (
                networking_subnet_dhcp_disabled,
            )

            check = networking_subnet_dhcp_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "subnet-1"
            assert result[0].resource_name == "production-subnet"
            assert (
                result[0].status_extended
                == "Subnet production-subnet (subnet-1) has DHCP enabled."
            )
            assert result[0].region == OPENSTACK_REGION

    def test_subnet_dhcp_disabled(self):
        """Test subnet with DHCP disabled (FAIL)."""
        network_client = mock.MagicMock()
        network_client.subnets = [
            Subnet(
                id="subnet-2",
                name="static-subnet",
                network_id="net-2",
                ip_version=4,
                cidr="10.0.0.0/24",
                gateway_ip="10.0.0.1",
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
                "prowler.providers.openstack.services.networking.networking_subnet_dhcp_disabled.networking_subnet_dhcp_disabled.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_subnet_dhcp_disabled.networking_subnet_dhcp_disabled import (
                networking_subnet_dhcp_disabled,
            )

            check = networking_subnet_dhcp_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "subnet-2"
            assert result[0].resource_name == "static-subnet"
            assert (
                result[0].status_extended
                == "Subnet static-subnet (subnet-2) on network net-2 has DHCP disabled, which may prevent instances from obtaining IP addresses automatically."
            )
            assert result[0].region == OPENSTACK_REGION

    def test_multiple_subnets_mixed_results(self):
        """Test multiple subnets with mixed DHCP configurations."""
        network_client = mock.MagicMock()
        network_client.subnets = [
            Subnet(
                id="subnet-1",
                name="dhcp-enabled-subnet",
                network_id="net-1",
                ip_version=4,
                cidr="192.168.1.0/24",
                gateway_ip="192.168.1.1",
                enable_dhcp=True,
                dns_nameservers=["8.8.8.8"],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            ),
            Subnet(
                id="subnet-2",
                name="dhcp-disabled-subnet",
                network_id="net-2",
                ip_version=4,
                cidr="10.0.0.0/24",
                gateway_ip="10.0.0.1",
                enable_dhcp=False,
                dns_nameservers=[],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.networking.networking_subnet_dhcp_disabled.networking_subnet_dhcp_disabled.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_subnet_dhcp_disabled.networking_subnet_dhcp_disabled import (
                networking_subnet_dhcp_disabled,
            )

            check = networking_subnet_dhcp_disabled()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1

            pass_result = [r for r in result if r.status == "PASS"][0]
            assert pass_result.resource_id == "subnet-1"
            assert pass_result.resource_name == "dhcp-enabled-subnet"
            assert pass_result.region == OPENSTACK_REGION
            assert (
                pass_result.status_extended
                == "Subnet dhcp-enabled-subnet (subnet-1) has DHCP enabled."
            )

            fail_result = [r for r in result if r.status == "FAIL"][0]
            assert fail_result.resource_id == "subnet-2"
            assert fail_result.resource_name == "dhcp-disabled-subnet"
            assert fail_result.region == OPENSTACK_REGION
            assert (
                fail_result.status_extended
                == "Subnet dhcp-disabled-subnet (subnet-2) on network net-2 has DHCP disabled, which may prevent instances from obtaining IP addresses automatically."
            )

    def test_subnet_ipv6_dhcp_enabled(self):
        """Test IPv6 subnet with DHCP enabled."""
        network_client = mock.MagicMock()
        network_client.subnets = [
            Subnet(
                id="subnet-ipv6",
                name="ipv6-subnet",
                network_id="net-1",
                ip_version=6,
                cidr="2001:db8::/64",
                gateway_ip="2001:db8::1",
                enable_dhcp=True,
                dns_nameservers=["2001:4860:4860::8888"],
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
                "prowler.providers.openstack.services.networking.networking_subnet_dhcp_disabled.networking_subnet_dhcp_disabled.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_subnet_dhcp_disabled.networking_subnet_dhcp_disabled import (
                networking_subnet_dhcp_disabled,
            )

            check = networking_subnet_dhcp_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "subnet-ipv6"
            assert result[0].resource_name == "ipv6-subnet"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Subnet ipv6-subnet (subnet-ipv6) has DHCP enabled."
            )
