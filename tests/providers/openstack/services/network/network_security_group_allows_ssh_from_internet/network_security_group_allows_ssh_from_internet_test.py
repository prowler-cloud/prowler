"""Tests for network_security_group_allows_ssh_from_internet check."""

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


class Test_network_security_group_allows_ssh_from_internet:
    """Test suite for network_security_group_allows_ssh_from_internet check."""

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
                "prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet import (
                network_security_group_allows_ssh_from_internet,
            )

            check = network_security_group_allows_ssh_from_internet()
            result = check.execute()

            assert len(result) == 0

    def test_security_group_without_ssh_exposed(self):
        """Test security group without SSH exposed to internet (PASS)."""
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
                "prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet import (
                network_security_group_allows_ssh_from_internet,
            )

            check = network_security_group_allows_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-1"
            assert result[0].resource_name == "web-servers"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group web-servers (sg-1) does not allow SSH (port 22) from the Internet."
            )

    def test_security_group_with_ssh_from_ipv4_internet(self):
        """Test security group with SSH exposed to IPv4 internet (FAIL)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-2",
                name="admin-servers",
                description="Admin servers",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-ssh",
                        security_group_id="sg-2",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=22,
                        port_range_max=22,
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
                "prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet import (
                network_security_group_allows_ssh_from_internet,
            )

            check = network_security_group_allows_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-2"
            assert result[0].resource_name == "admin-servers"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group admin-servers (sg-2) allows unrestricted SSH access (port 22) from the Internet via rule rule-ssh (tcp/0.0.0.0/0:22-22)."
            )

    def test_security_group_with_ssh_from_ipv6_internet(self):
        """Test security group with SSH exposed to IPv6 internet (FAIL)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-3",
                name="ipv6-servers",
                description="IPv6 servers",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-ssh-ipv6",
                        security_group_id="sg-3",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv6",
                        port_range_min=22,
                        port_range_max=22,
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
                "prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet import (
                network_security_group_allows_ssh_from_internet,
            )

            check = network_security_group_allows_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-3"
            assert result[0].resource_name == "ipv6-servers"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group ipv6-servers (sg-3) allows unrestricted SSH access (port 22) from the Internet via rule rule-ssh-ipv6 (tcp/::/0:22-22)."
            )

    def test_security_group_with_ssh_from_restricted_cidr(self):
        """Test security group with SSH from specific CIDR (PASS)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-4",
                name="restricted-ssh",
                description="SSH from specific IP",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-restricted",
                        security_group_id="sg-4",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=22,
                        port_range_max=22,
                        remote_ip_prefix="203.0.113.0/24",
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
                "prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet import (
                network_security_group_allows_ssh_from_internet,
            )

            check = network_security_group_allows_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-4"
            assert result[0].resource_name == "restricted-ssh"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group restricted-ssh (sg-4) does not allow SSH (port 22) from the Internet."
            )

    def test_security_group_with_ssh_port_range(self):
        """Test security group with port range including SSH (FAIL)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-5",
                name="port-range",
                description="Port range including SSH",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-range",
                        security_group_id="sg-5",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=20,
                        port_range_max=25,
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
                "prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet import (
                network_security_group_allows_ssh_from_internet,
            )

            check = network_security_group_allows_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-5"
            assert result[0].resource_name == "port-range"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group port-range (sg-5) allows unrestricted SSH access (port 22) from the Internet via rule rule-range (tcp/0.0.0.0/0:20-25)."
            )

    def test_security_group_with_ssh_from_security_group(self):
        """Test security group with SSH from another security group (PASS)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-6",
                name="sg-referenced",
                description="SSH from security group",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-sg-ref",
                        security_group_id="sg-6",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=22,
                        port_range_max=22,
                        remote_ip_prefix=None,
                        remote_group_id="sg-bastion",
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
                "prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet import (
                network_security_group_allows_ssh_from_internet,
            )

            check = network_security_group_allows_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-6"
            assert result[0].resource_name == "sg-referenced"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group sg-referenced (sg-6) does not allow SSH (port 22) from the Internet."
            )

    def test_security_group_with_egress_ssh(self):
        """Test security group with egress SSH rule (PASS)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-7",
                name="egress-only",
                description="Egress SSH",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-egress",
                        security_group_id="sg-7",
                        direction="egress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=22,
                        port_range_max=22,
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
                "prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet import (
                network_security_group_allows_ssh_from_internet,
            )

            check = network_security_group_allows_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-7"
            assert result[0].resource_name == "egress-only"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group egress-only (sg-7) does not allow SSH (port 22) from the Internet."
            )

    def test_security_group_with_all_tcp_from_internet(self):
        """Test security group allowing all TCP ports from internet (FAIL).

        In OpenStack Neutron, protocol=tcp with port_range_min=None and
        port_range_max=None means all TCP ports are allowed.
        """
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-all-tcp",
                name="all-tcp-open",
                description="All TCP ports open",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-all-tcp",
                        security_group_id="sg-all-tcp",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=None,
                        port_range_max=None,
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
                "prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet import (
                network_security_group_allows_ssh_from_internet,
            )

            check = network_security_group_allows_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-all-tcp"
            assert result[0].resource_name == "all-tcp-open"
            assert result[0].region == OPENSTACK_REGION

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
                        port_range_min=22,
                        port_range_max=22,
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
                "prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_allows_ssh_from_internet.network_security_group_allows_ssh_from_internet import (
                network_security_group_allows_ssh_from_internet,
            )

            check = network_security_group_allows_ssh_from_internet()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
