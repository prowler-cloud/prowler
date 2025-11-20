from unittest.mock import patch

from prowler.providers.stackit.services.iaas.iaas_service import (
    IaaSService,
    SecurityGroupRule,
)
from tests.providers.stackit.stackit_fixtures import (
    STACKIT_PROJECT_ID,
    set_mocked_stackit_provider,
)


def mock_iaas_get_stackit_client(_):
    """Mock the _get_stackit_client method to avoid real SDK initialization."""
    return "mock_client"


def mock_iaas_list_public_ips(_):
    """Mock the _list_public_ips method to populate public_nic_ids."""
    # Simulate that we found 2 public IPs attached to NICs
    # This will be called during __init__ so we need to modify the instance


def mock_iaas_list_server_nics(_):
    """Mock the _list_server_nics method to populate server_nics and in_use_sg_ids."""


def mock_iaas_list_security_groups(_):
    """Mock the _list_security_groups method to populate security_groups list."""


def mock_iaas_list_security_group_rules(_, client, security_group_id):
    """Mock the _list_security_group_rules method to return mock rules."""
    # Return different rules based on security group ID for testing
    if security_group_id == "sg-with-rules":
        return [
            SecurityGroupRule(
                id="rule-1",
                direction="ingress",
                protocol="tcp",
                ip_range="0.0.0.0/0",
                port_range_min=22,
                port_range_max=22,
            ),
            SecurityGroupRule(
                id="rule-2",
                direction="egress",
                protocol="tcp",
                ip_range="10.0.0.0/8",
                port_range_min=443,
                port_range_max=443,
            ),
        ]
    return []


@patch(
    "prowler.providers.stackit.services.iaas.iaas_service.IaaSService._get_stackit_client",
    new=mock_iaas_get_stackit_client,
)
@patch(
    "prowler.providers.stackit.services.iaas.iaas_service.IaaSService._list_public_ips",
    new=mock_iaas_list_public_ips,
)
@patch(
    "prowler.providers.stackit.services.iaas.iaas_service.IaaSService._list_server_nics",
    new=mock_iaas_list_server_nics,
)
@patch(
    "prowler.providers.stackit.services.iaas.iaas_service.IaaSService._list_security_groups",
    new=mock_iaas_list_security_groups,
)
class Test_IaaS_Service:
    def test_service_initialization(self):
        """Test that the IaaS service initializes correctly."""
        iaas_service = IaaSService(set_mocked_stackit_provider())

        assert iaas_service.project_id == STACKIT_PROJECT_ID
        assert iaas_service.api_token is not None
        assert isinstance(iaas_service.security_groups, list)
        assert isinstance(iaas_service.server_nics, list)
        assert isinstance(iaas_service.public_nic_ids, set)
        assert isinstance(iaas_service.in_use_sg_ids, set)

    def test_service_project_id(self):
        """Test that the service correctly extracts project_id from provider."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        assert iaas_service.project_id == STACKIT_PROJECT_ID

    def test_service_api_token(self):
        """Test that the service correctly extracts API token from provider."""
        custom_token = "custom-test-token"
        provider = set_mocked_stackit_provider(api_token=custom_token)
        iaas_service = IaaSService(provider)
        assert iaas_service.api_token == custom_token

    def test_security_groups_list_structure(self):
        """Test that security_groups is properly initialized as a list."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        assert hasattr(iaas_service, "security_groups")
        assert isinstance(iaas_service.security_groups, list)

    def test_public_nic_ids_set_structure(self):
        """Test that public_nic_ids is properly initialized as a set."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        assert hasattr(iaas_service, "public_nic_ids")
        assert isinstance(iaas_service.public_nic_ids, set)

    def test_in_use_sg_ids_set_structure(self):
        """Test that in_use_sg_ids is properly initialized as a set."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        assert hasattr(iaas_service, "in_use_sg_ids")
        assert isinstance(iaas_service.in_use_sg_ids, set)


# Test SecurityGroupRule helper methods
class Test_SecurityGroupRule:
    def test_is_unrestricted_with_none(self):
        """Test that None ip_range is considered unrestricted."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range=None,
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_unrestricted() is True

    def test_is_unrestricted_with_cidr(self):
        """Test that 0.0.0.0/0 is considered unrestricted."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_unrestricted() is True

    def test_is_unrestricted_with_ipv6(self):
        """Test that ::/0 is considered unrestricted."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="::/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_unrestricted() is True

    def test_is_restricted_with_specific_ip(self):
        """Test that specific IP range is considered restricted."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="10.0.0.0/8",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_unrestricted() is False

    def test_is_ingress_true(self):
        """Test that ingress direction is properly detected."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_ingress() is True

    def test_is_ingress_false(self):
        """Test that egress direction returns false for is_ingress."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="egress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_ingress() is False

    def test_is_tcp_with_tcp_protocol(self):
        """Test that TCP protocol is detected correctly."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_tcp() is True

    def test_is_tcp_with_none_protocol(self):
        """Test that None protocol is treated as TCP (all protocols)."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol=None,
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_tcp() is True

    def test_is_tcp_with_all_protocol(self):
        """Test that 'all' protocol is treated as TCP."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="all",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_tcp() is True

    def test_is_tcp_with_udp_protocol(self):
        """Test that UDP protocol returns false for is_tcp."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="udp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_tcp() is False

    def test_includes_port_exact_match(self):
        """Test that exact port match is detected."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.includes_port(22) is True

    def test_includes_port_in_range(self):
        """Test that port within range is detected."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=20,
            port_range_max=25,
        )
        assert rule.includes_port(22) is True
        assert rule.includes_port(20) is True
        assert rule.includes_port(25) is True

    def test_includes_port_outside_range(self):
        """Test that port outside range is not detected."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=80,
            port_range_max=443,
        )
        assert rule.includes_port(22) is False

    def test_includes_port_with_none_range(self):
        """Test that None port range means all ports."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=None,
            port_range_max=None,
        )
        assert rule.includes_port(22) is True
        assert rule.includes_port(443) is True
        assert rule.includes_port(65535) is True
