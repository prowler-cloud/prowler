"""Tests for networking_security_group_allows_all_ingress_from_internet check."""

from unittest import mock

from prowler.providers.openstack.services.networking.networking_service import (
    SecurityGroup,
    SecurityGroupRule,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)

CHECK_PATH = "prowler.providers.openstack.services.networking.networking_security_group_allows_all_ingress_from_internet.networking_security_group_allows_all_ingress_from_internet"


class Test_networking_security_group_allows_all_ingress_from_internet:
    """Test suite for networking_security_group_allows_all_ingress_from_internet check."""

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
                f"{CHECK_PATH}.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_security_group_allows_all_ingress_from_internet.networking_security_group_allows_all_ingress_from_internet import (
                networking_security_group_allows_all_ingress_from_internet,
            )

            check = networking_security_group_allows_all_ingress_from_internet()
            result = check.execute()

            assert len(result) == 0

    def test_security_group_with_specific_tcp_rule(self):
        """Test SG with specific TCP port from internet (PASS - not all ingress)."""
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
                f"{CHECK_PATH}.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_security_group_allows_all_ingress_from_internet.networking_security_group_allows_all_ingress_from_internet import (
                networking_security_group_allows_all_ingress_from_internet,
            )

            check = networking_security_group_allows_all_ingress_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-1"
            assert result[0].resource_name == "web-servers"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group web-servers (sg-1) does not allow all ingress traffic from the Internet."
            )

    def test_security_group_with_all_ingress_ipv4(self):
        """Test SG with all ingress from IPv4 internet (FAIL)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-2",
                name="wide-open",
                description="Wide open security group",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-all",
                        security_group_id="sg-2",
                        direction="ingress",
                        protocol=None,
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
                f"{CHECK_PATH}.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_security_group_allows_all_ingress_from_internet.networking_security_group_allows_all_ingress_from_internet import (
                networking_security_group_allows_all_ingress_from_internet,
            )

            check = networking_security_group_allows_all_ingress_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-2"
            assert result[0].resource_name == "wide-open"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group wide-open (sg-2) allows all ingress traffic (any protocol, any port) from the Internet via rule rule-all (0.0.0.0/0)."
            )

    def test_security_group_with_all_ingress_ipv6(self):
        """Test SG with all ingress from IPv6 internet (FAIL)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-3",
                name="ipv6-open",
                description="IPv6 open security group",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-all-v6",
                        security_group_id="sg-3",
                        direction="ingress",
                        protocol=None,
                        ethertype="IPv6",
                        port_range_min=None,
                        port_range_max=None,
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
                f"{CHECK_PATH}.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_security_group_allows_all_ingress_from_internet.networking_security_group_allows_all_ingress_from_internet import (
                networking_security_group_allows_all_ingress_from_internet,
            )

            check = networking_security_group_allows_all_ingress_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-3"
            assert result[0].resource_name == "ipv6-open"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group ipv6-open (sg-3) allows all ingress traffic (any protocol, any port) from the Internet via rule rule-all-v6 (::/0)."
            )

    def test_security_group_with_all_ingress_from_security_group(self):
        """Test SG with all ingress from another security group (PASS)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-4",
                name="sg-referenced",
                description="All ingress from SG",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-sg-ref",
                        security_group_id="sg-4",
                        direction="ingress",
                        protocol=None,
                        ethertype="IPv4",
                        port_range_min=None,
                        port_range_max=None,
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
                f"{CHECK_PATH}.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_security_group_allows_all_ingress_from_internet.networking_security_group_allows_all_ingress_from_internet import (
                networking_security_group_allows_all_ingress_from_internet,
            )

            check = networking_security_group_allows_all_ingress_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-4"
            assert result[0].resource_name == "sg-referenced"
            assert result[0].region == OPENSTACK_REGION

    def test_security_group_with_no_prefix_no_group(self):
        """Test SG with no remote_ip_prefix and no remote_group_id (FAIL).

        In OpenStack, a rule with no remote_ip_prefix and no remote_group_id
        means traffic from any source is allowed.
        """
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-5",
                name="implicit-open",
                description="Implicitly open security group",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-implicit",
                        security_group_id="sg-5",
                        direction="ingress",
                        protocol=None,
                        ethertype="IPv4",
                        port_range_min=None,
                        port_range_max=None,
                        remote_ip_prefix=None,
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
                f"{CHECK_PATH}.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_security_group_allows_all_ingress_from_internet.networking_security_group_allows_all_ingress_from_internet import (
                networking_security_group_allows_all_ingress_from_internet,
            )

            check = networking_security_group_allows_all_ingress_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-5"
            assert result[0].resource_name == "implicit-open"
            assert result[0].region == OPENSTACK_REGION
            assert (
                result[0].status_extended
                == "Security group implicit-open (sg-5) allows all ingress traffic (any protocol, any port) from the Internet via rule rule-implicit (0.0.0.0/0)."
            )

    def test_security_group_with_all_protocol_egress(self):
        """Test SG with all-protocol egress rule (PASS - egress only)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-6",
                name="egress-open",
                description="All egress allowed",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-egress",
                        security_group_id="sg-6",
                        direction="egress",
                        protocol=None,
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
                f"{CHECK_PATH}.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_security_group_allows_all_ingress_from_internet.networking_security_group_allows_all_ingress_from_internet import (
                networking_security_group_allows_all_ingress_from_internet,
            )

            check = networking_security_group_allows_all_ingress_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-6"
            assert result[0].resource_name == "egress-open"
            assert result[0].region == OPENSTACK_REGION

    def test_security_group_with_all_tcp_from_internet(self):
        """Test SG with all TCP (not all protocols) from internet (PASS).

        This check only flags rules with NO protocol restriction (all protocols).
        A rule allowing all TCP ports is not flagged by this check.
        """
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-7",
                name="all-tcp",
                description="All TCP ports open",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-all-tcp",
                        security_group_id="sg-7",
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
                f"{CHECK_PATH}.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_security_group_allows_all_ingress_from_internet.networking_security_group_allows_all_ingress_from_internet import (
                networking_security_group_allows_all_ingress_from_internet,
            )

            check = networking_security_group_allows_all_ingress_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-7"
            assert result[0].resource_name == "all-tcp"
            assert result[0].region == OPENSTACK_REGION

    def test_multiple_security_groups_mixed(self):
        """Test multiple security groups with mixed results."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-pass",
                name="secure-sg",
                description="Secure SG",
                security_group_rules=[
                    SecurityGroupRule(
                        id="rule-pass",
                        security_group_id="sg-pass",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        port_range_min=443,
                        port_range_max=443,
                        remote_ip_prefix="0.0.0.0/0",
                        remote_group_id=None,
                    ),
                ],
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
                        protocol=None,
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
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                f"{CHECK_PATH}.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_security_group_allows_all_ingress_from_internet.networking_security_group_allows_all_ingress_from_internet import (
                networking_security_group_allows_all_ingress_from_internet,
            )

            check = networking_security_group_allows_all_ingress_from_internet()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
