from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.stackit.exceptions.exceptions import StackITInvalidTokenError
from prowler.providers.stackit.services.iaas.iaas_service import (
    IaaSService,
    SecurityGroupRule,
)
from tests.providers.stackit.stackit_fixtures import (
    STACKIT_PROJECT_ID,
    set_mocked_stackit_provider,
)


def mock_iaas_fetch_all_regions(_):
    """Mock the _fetch_all_regions method to avoid real API calls."""


@patch(
    "prowler.providers.stackit.services.iaas.iaas_service.IaaSService._fetch_all_regions",
    new=mock_iaas_fetch_all_regions,
)
class Test_IaaS_Service:
    def test_service_initialization(self):
        """Test that the IaaS service initializes correctly."""
        iaas_service = IaaSService(set_mocked_stackit_provider())

        assert iaas_service.project_id == STACKIT_PROJECT_ID
        assert iaas_service.service_account_key_path is not None
        assert isinstance(iaas_service.security_groups, list)
        assert isinstance(iaas_service.server_nics, list)
        assert isinstance(iaas_service.in_use_sg_ids, set)
        assert iaas_service.scan_unused_services is False

    def test_service_project_id(self):
        """Test that the service correctly extracts project_id from provider."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        assert iaas_service.project_id == STACKIT_PROJECT_ID

    def test_service_service_account_key_path(self):
        """Test that the service correctly extracts the SA key path from provider."""
        custom_path = "/tmp/custom-sa.json"
        provider = set_mocked_stackit_provider(service_account_key_path=custom_path)
        iaas_service = IaaSService(provider)
        assert iaas_service.service_account_key_path == custom_path

    def test_security_groups_list_structure(self):
        """Test that security_groups is properly initialized as a list."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        assert hasattr(iaas_service, "security_groups")
        assert isinstance(iaas_service.security_groups, list)

    def test_in_use_sg_ids_set_structure(self):
        """Test that in_use_sg_ids is properly initialized as a set."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        assert hasattr(iaas_service, "in_use_sg_ids")
        assert isinstance(iaas_service.in_use_sg_ids, set)

    @pytest.mark.parametrize(
        "method_name,client_method_name",
        [
            ("_list_server_nics", "list_project_nics"),
            ("_list_security_groups", "list_security_groups"),
            ("_list_security_group_rules", "list_security_group_rules"),
        ],
    )
    def test_list_methods_propagate_api_errors(self, method_name, client_method_name):
        """API/auth failures must fail the scan instead of returning empty data."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        client = MagicMock()
        getattr(client, client_method_name).side_effect = StackITInvalidTokenError(
            message="Invalid token"
        )

        with pytest.raises(StackITInvalidTokenError):
            if method_name == "_list_security_group_rules":
                getattr(iaas_service, method_name)(client, "eu01", "sg-1")
            else:
                getattr(iaas_service, method_name)(client, "eu01")

    def test_security_group_parsing_errors_are_skipped_locally(self):
        """Malformed resources are skipped while valid resources are retained."""

        class MalformedSecurityGroup:
            @property
            def id(self):
                raise ValueError("malformed security group")

        iaas_service = IaaSService(set_mocked_stackit_provider())
        client = MagicMock()
        client.list_security_groups.return_value = [
            MalformedSecurityGroup(),
            {"id": "sg-1", "name": "valid-sg"},
        ]
        client.list_security_group_rules.return_value = []

        iaas_service._list_security_groups(client, "eu01")

        assert len(iaas_service.security_groups) == 1
        assert iaas_service.security_groups[0].id == "sg-1"

    def test_in_use_considers_all_nics_not_only_public(self):
        """A SG attached to any NIC (public or private) counts as in_use."""
        iaas_service = IaaSService(set_mocked_stackit_provider())

        # NIC without a public IP, but has a security group attached
        private_nic = {"id": "nic-private", "security_groups": ["sg-private"]}
        used = iaas_service._get_used_security_group_ids([private_nic])

        assert "sg-private" in used

    def test_in_use_sg_ids_populated_via_list_server_nics(self):
        """_list_server_nics marks SGs on any NIC as in_use."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        client = MagicMock()
        client.list_project_nics.return_value = [
            {"id": "nic-1", "security_groups": ["sg-1"]},
            {"id": "nic-2", "security_groups": ["sg-2"]},
        ]

        iaas_service._list_server_nics(client, "eu01")

        assert "sg-1" in iaas_service.in_use_sg_ids
        assert "sg-2" in iaas_service.in_use_sg_ids


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


class Test_IaaS_Service_Extract_Items:
    """Cover ``IaaSService._extract_items`` against the three response shapes the
    StackIT SDK can return. The previous implementation matched ``dict`` via
    ``hasattr(response, "items")`` and returned the bound method instead of the
    items field.
    """

    def test_extract_items_from_sdk_model(self):
        """SDK models expose ``items`` as a non-callable attribute."""
        response = MagicMock(spec=["items"])
        sentinel = [{"id": "sg-1"}, {"id": "sg-2"}]
        response.items = sentinel
        assert IaaSService._extract_items(response, "endpoint") is sentinel

    def test_extract_items_from_dict_with_items_key(self):
        """Dict responses must use the ``items`` key, not ``dict.items()``."""
        response = {"items": [{"id": "sg-1"}]}
        assert IaaSService._extract_items(response, "endpoint") == [{"id": "sg-1"}]

    def test_extract_items_from_empty_dict(self):
        """An empty dict yields an empty list, not the ``dict.items`` method."""
        assert IaaSService._extract_items({}, "endpoint") == []

    def test_extract_items_from_list(self):
        """A plain list response is returned as-is."""
        response = [{"id": "sg-1"}]
        assert IaaSService._extract_items(response, "endpoint") is response

    def test_extract_items_unknown_shape_returns_empty(self):
        """Unknown shapes fall back to an empty list and log a warning."""
        assert IaaSService._extract_items(42, "endpoint") == []

    def test_extract_items_ignores_dict_items_method(self):
        """Regression: ``dict`` exposes ``items`` as a method; ensure the
        ``isinstance(dict)`` branch wins and we do not return the bound method.
        """
        result = IaaSService._extract_items({"items": ["ok"]}, "endpoint")
        assert result == ["ok"]
        assert not callable(result)
