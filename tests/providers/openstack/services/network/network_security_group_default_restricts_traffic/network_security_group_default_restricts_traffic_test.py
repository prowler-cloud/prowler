"""Tests for network_security_group_default_restricts_traffic check."""

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


class Test_network_security_group_default_restricts_traffic:
    """Test suite for network_security_group_default_restricts_traffic check."""  # noqa: E501

    def test_no_security_groups(self):
        """Test when no security groups exist."""
        network_client = mock.MagicMock()
        network_client.security_groups = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",  # noqa: E501
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic.network_client",  # noqa: E501
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic import (  # noqa: E501
                network_security_group_default_restricts_traffic,
            )

            check = network_security_group_default_restricts_traffic()
            result = check.execute()

            assert len(result) == 0

    def test_no_default_security_groups(self):
        """Test when only custom security groups exist."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-1",
                name="custom-sg",
                description="Custom security group",
                security_group_rules=[],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=False,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",  # noqa: E501
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic.network_client",  # noqa: E501
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic import (  # noqa: E501
                network_security_group_default_restricts_traffic,
            )

            check = network_security_group_default_restricts_traffic()
            result = check.execute()

            assert len(result) == 0

    def test_default_security_group_unmodified(self):
        """Test default security group with standard 4 rules (PASS)."""
        network_client = mock.MagicMock()

        # Default security group with 4 standard rules
        default_rules = [
            SecurityGroupRule(
                id="rule-1",
                security_group_id="sg-default",
                direction="egress",
                protocol=None,
                ethertype="IPv4",
                port_range_min=None,
                port_range_max=None,
                remote_ip_prefix="0.0.0.0/0",
                remote_group_id=None,
            ),
            SecurityGroupRule(
                id="rule-2",
                security_group_id="sg-default",
                direction="egress",
                protocol=None,
                ethertype="IPv6",
                port_range_min=None,
                port_range_max=None,
                remote_ip_prefix="::/0",
                remote_group_id=None,
            ),
            SecurityGroupRule(
                id="rule-3",
                security_group_id="sg-default",
                direction="ingress",
                protocol=None,
                ethertype="IPv4",
                port_range_min=None,
                port_range_max=None,
                remote_ip_prefix=None,
                remote_group_id="sg-default",
            ),
            SecurityGroupRule(
                id="rule-4",
                security_group_id="sg-default",
                direction="ingress",
                protocol=None,
                ethertype="IPv6",
                port_range_min=None,
                port_range_max=None,
                remote_ip_prefix=None,
                remote_group_id="sg-default",
            ),
        ]

        network_client.security_groups = [
            SecurityGroup(
                id="sg-default",
                name="default",
                description="Default security group",
                security_group_rules=default_rules,
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=True,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",  # noqa: E501
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic.network_client",  # noqa: E501
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic import (  # noqa: E501
                network_security_group_default_restricts_traffic,
            )

            check = network_security_group_default_restricts_traffic()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sg-default"
            assert result[0].resource_name == "default"
            assert "has not been modified" in result[0].status_extended
            assert "4 rules" in result[0].status_extended

    def test_default_security_group_modified(self):
        """Test default security group with custom rules added (FAIL)."""
        network_client = mock.MagicMock()

        # Default security group with more than 4 rules (custom rules added)
        modified_rules = [
            SecurityGroupRule(
                id="rule-1",
                security_group_id="sg-default",
                direction="egress",
                protocol=None,
                ethertype="IPv4",
                port_range_min=None,
                port_range_max=None,
                remote_ip_prefix="0.0.0.0/0",
                remote_group_id=None,
            ),
            SecurityGroupRule(
                id="rule-2",
                security_group_id="sg-default",
                direction="egress",
                protocol=None,
                ethertype="IPv6",
                port_range_min=None,
                port_range_max=None,
                remote_ip_prefix="::/0",
                remote_group_id=None,
            ),
            SecurityGroupRule(
                id="rule-3",
                security_group_id="sg-default",
                direction="ingress",
                protocol=None,
                ethertype="IPv4",
                port_range_min=None,
                port_range_max=None,
                remote_ip_prefix=None,
                remote_group_id="sg-default",
            ),
            SecurityGroupRule(
                id="rule-4",
                security_group_id="sg-default",
                direction="ingress",
                protocol=None,
                ethertype="IPv6",
                port_range_min=None,
                port_range_max=None,
                remote_ip_prefix=None,
                remote_group_id="sg-default",
            ),
            # Custom rule added
            SecurityGroupRule(
                id="rule-custom",
                security_group_id="sg-default",
                direction="ingress",
                protocol="tcp",
                ethertype="IPv4",
                port_range_min=22,
                port_range_max=22,
                remote_ip_prefix="0.0.0.0/0",
                remote_group_id=None,
            ),
        ]

        network_client.security_groups = [
            SecurityGroup(
                id="sg-default",
                name="default",
                description="Default security group",
                security_group_rules=modified_rules,
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=True,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",  # noqa: E501
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic.network_client",  # noqa: E501
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic import (  # noqa: E501
                network_security_group_default_restricts_traffic,
            )

            check = network_security_group_default_restricts_traffic()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-default"
            assert "has been modified" in result[0].status_extended
            assert "5 custom rules" in result[0].status_extended

    def test_default_security_group_empty(self):
        """Test default security group with no rules (PASS)."""
        network_client = mock.MagicMock()
        network_client.security_groups = [
            SecurityGroup(
                id="sg-default",
                name="default",
                description="Default security group",
                security_group_rules=[],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=True,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",  # noqa: E501
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic.network_client",  # noqa: E501
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic import (  # noqa: E501
                network_security_group_default_restricts_traffic,
            )

            check = network_security_group_default_restricts_traffic()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_multiple_default_security_groups_mixed(self):
        """Test multiple default security groups with mixed results."""
        network_client = mock.MagicMock()

        # One unmodified, one modified
        network_client.security_groups = [
            SecurityGroup(
                id="sg-default-1",
                name="default",
                description="Default SG 1",
                security_group_rules=[
                    SecurityGroupRule(
                        id=f"rule-{i}",
                        security_group_id="sg-default-1",
                        direction="egress",
                        protocol=None,
                        ethertype="IPv4",
                        port_range_min=None,
                        port_range_max=None,
                        remote_ip_prefix="0.0.0.0/0",
                        remote_group_id=None,
                    )
                    for i in range(4)
                ],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=True,
                tags=[],
            ),
            SecurityGroup(
                id="sg-default-2",
                name="default",
                description="Default SG 2",
                security_group_rules=[
                    SecurityGroupRule(
                        id=f"rule-{i}",
                        security_group_id="sg-default-2",
                        direction="egress",
                        protocol=None,
                        ethertype="IPv4",
                        port_range_min=None,
                        port_range_max=None,
                        remote_ip_prefix="0.0.0.0/0",
                        remote_group_id=None,
                    )
                    for i in range(10)  # Modified with 10 rules
                ],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                is_default=True,
                tags=[],
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",  # noqa: E501
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic.network_client",  # noqa: E501
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_security_group_default_restricts_traffic.network_security_group_default_restricts_traffic import (  # noqa: E501
                network_security_group_default_restricts_traffic,
            )

            check = network_security_group_default_restricts_traffic()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
