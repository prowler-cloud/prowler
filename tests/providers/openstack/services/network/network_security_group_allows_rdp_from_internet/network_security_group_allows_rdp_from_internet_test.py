"""Tests for network_security_group_allows_rdp_from_internet check."""

from unittest import mock

from prowler.providers.openstack.services.network.network_service import (
    SecurityGroup,
    SecurityGroupRule,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_network_security_group_allows_rdp_from_internet:
    """Test suite for network_security_group_allows_rdp_from_internet check."""

    def test_no_security_groups(self):
        """Test when no security groups exist."""
        network_client = mock.MagicMock()
        network_client.security_groups = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet import (
                network_security_group_allows_rdp_from_internet,
            )

            check = network_security_group_allows_rdp_from_internet()
            result = check.execute()

            assert len(result) == 0

    def test_security_group_without_rdp_exposed(self):
        """Test security group without RDP exposed to internet (PASS)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-1",
                name="web-servers",
                description="Web servers security group",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        security_group_id="sg-1",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=80,
                        port_range_max=80,
                        remote_ip_prefix="0.0.0.0/0",
                        remote_group_id=None,
                    ),
                ],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=False,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet import (
                network_security_group_allows_rdp_from_internet,
            )

            check = network_security_group_allows_rdp_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-1"
            assert result[0].resource_name == "web-servers"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group web-servers (sg-1) does not allow RDP (port 3389) from the Internet."
            )

    def test_security_group_with_rdp_from_ipv4_internet(self):
        """Test security group with RDP exposed to IPv4 internet (FAIL)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-2",
                name="windows-servers",
                description="Windows servers",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-rdp",
                        security_group_id="sg-2",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=3389,
                        port_range_max=3389,
                        remote_ip_prefix="0.0.0.0/0",
                        remote_group_id=None,
                    ),
                ],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=False,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet import (
                network_security_group_allows_rdp_from_internet,
            )

            check = network_security_group_allows_rdp_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-2"
            assert result[0].resource_name == "windows-servers"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group windows-servers (sg-2) allows unrestricted RDP access (port 3389) from the Internet via rule rule-rdp (tcp/0.0.0.0/0:3389-3389)."
            )

    def test_security_group_with_rdp_from_ipv6_internet(self):
        """Test security group with RDP exposed to IPv6 internet (FAIL)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-3",
                name="ipv6-windows",
                description="IPv6 Windows servers",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-rdp-ipv6",
                        security_group_id="sg-3",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv6",
                        port_range_min=3389,
                        port_range_max=3389,
                        remote_ip_prefix="::/0",
                        remote_group_id=None,
                    ),
                ],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=False,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet import (
                network_security_group_allows_rdp_from_internet,
            )

            check = network_security_group_allows_rdp_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-3"
            assert result[0].resource_name == "ipv6-windows"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group ipv6-windows (sg-3) allows unrestricted RDP access (port 3389) from the Internet via rule rule-rdp-ipv6 (tcp/::/0:3389-3389)."
            )

    def test_security_group_with_rdp_from_restricted_cidr(self):
        """Test security group with RDP from specific CIDR (PASS)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-4",
                name="restricted-rdp",
                description="RDP from specific IP",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-restricted",
                        security_group_id="sg-4",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=3389,
                        port_range_max=3389,
                        remote_ip_prefix="198.51.100.0/24",
                        remote_group_id=None,
                    ),
                ],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=False,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet import (
                network_security_group_allows_rdp_from_internet,
            )

            check = network_security_group_allows_rdp_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-4"
            assert result[0].resource_name == "restricted-rdp"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group restricted-rdp (sg-4) does not allow RDP (port 3389) from the Internet."
            )

    def test_security_group_with_rdp_port_range(self):
        """Test security group with port range including RDP (FAIL)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-5",
                name="port-range",
                description="Port range including RDP",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-range",
                        security_group_id="sg-5",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=3000,
                        port_range_max=4000,
                        remote_ip_prefix="0.0.0.0/0",
                        remote_group_id=None,
                    ),
                ],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=False,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet import (
                network_security_group_allows_rdp_from_internet,
            )

            check = network_security_group_allows_rdp_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-5"
            assert result[0].resource_name == "port-range"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group port-range (sg-5) allows unrestricted RDP access (port 3389) from the Internet via rule rule-range (tcp/0.0.0.0/0:3000-4000)."
            )

    def test_multiple_security_groups_mixed(self):
        """Test multiple security groups with mixed results."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-pass",
                name="secure-sg",
                description="Secure SG",
                security_group_rules=[],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=False,
                tags=[],
            ),
            SecurityGroup(
                id="sg-fail",
                name="insecure-sg",
                description="Insecure SG",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-fail",
                        security_group_id="sg-fail",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=3389,
                        port_range_max=3389,
                        remote_ip_prefix="0.0.0.0/0",
                        remote_group_id=None,
                    ),
                ],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=False,
                tags=[],
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_rdp_from_internet.network_security_group_allows_rdp_from_internet import (
                network_security_group_allows_rdp_from_internet,
            )

            check = network_security_group_allows_rdp_from_internet()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
