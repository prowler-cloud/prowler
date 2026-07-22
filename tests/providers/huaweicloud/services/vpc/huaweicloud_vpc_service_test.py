from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.vpc.vpc_service import (
    VPC,
    SecurityGroupRule,
    SecurityGroups,
    VPCs,
)
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"


def _provider_with_client(regional_client):
    """Return a mocked provider whose regional client is the given mock."""
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.generate_regional_clients = mock.MagicMock(
        return_value={REGION: regional_client}
    )
    return provider


class TestVPCService:
    def test_list_vpcs_and_security_groups_parses(self):
        vpc = SimpleNamespace(
            id="vpc-1",
            name="default-vpc",
            cidr="10.0.0.0/16",
            status="ACTIVE",
            description="primary vpc",
            created_at="2024-01-01T00:00:00Z",
        )
        rule = SimpleNamespace(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ethertype="IPv4",
            port_range_min=22,
            port_range_max=22,
            remote_ip_prefix="0.0.0.0/0",
            remote_group_id="",
            description="ssh open",
        )
        sg = SimpleNamespace(
            id="sg-1",
            name="web-sg",
            vpc_id="vpc-1",
            description="web security group",
            security_group_rules=[rule],
        )

        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_vpcs.return_value = SimpleNamespace(vpcs=[vpc])
        regional_client.list_security_groups.return_value = SimpleNamespace(
            security_groups=[sg]
        )

        vpc_service = VPC(_provider_with_client(regional_client))

        # VPCs
        assert len(vpc_service.vpcs) == 1
        parsed_vpc = vpc_service.vpcs["vpc-1"]
        assert isinstance(parsed_vpc, VPCs)
        assert parsed_vpc.name == "default-vpc"
        assert parsed_vpc.region == REGION
        assert parsed_vpc.cidr == "10.0.0.0/16"
        assert parsed_vpc.status == "ACTIVE"

        # Security Groups
        assert len(vpc_service.security_groups) == 1
        parsed_sg = vpc_service.security_groups["sg-1"]
        assert isinstance(parsed_sg, SecurityGroups)
        assert parsed_sg.name == "web-sg"
        assert parsed_sg.region == REGION
        assert parsed_sg.vpc_id == "vpc-1"
        assert len(parsed_sg.rules) == 1

        # Security Group Rule (fields the checks depend on)
        parsed_rule = parsed_sg.rules[0]
        assert isinstance(parsed_rule, SecurityGroupRule)
        assert parsed_rule.direction == "ingress"
        assert parsed_rule.protocol == "tcp"
        assert parsed_rule.remote_ip_prefix == "0.0.0.0/0"
        assert parsed_rule.port_range_min == 22
        assert parsed_rule.port_range_max == 22

    def test_rule_fields_none_from_sdk_are_coerced(self):
        # The Huawei SDK returns optional rule fields explicitly set to None
        # (protocol/remote_ip_prefix/description), which must not raise a
        # pydantic ValidationError.
        rule = SimpleNamespace(
            id="rule-1",
            direction=None,
            protocol=None,
            ethertype=None,
            port_range_min=None,
            port_range_max=None,
            remote_ip_prefix=None,
            remote_group_id=None,
            description=None,
        )
        sg = SimpleNamespace(
            id="sg-1",
            name=None,
            vpc_id=None,
            description=None,
            security_group_rules=[rule],
        )
        vpc = SimpleNamespace(
            id="vpc-1",
            name=None,
            cidr=None,
            status=None,
            description=None,
            created_at=None,
        )

        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_vpcs.return_value = SimpleNamespace(vpcs=[vpc])
        regional_client.list_security_groups.return_value = SimpleNamespace(
            security_groups=[sg]
        )

        vpc_service = VPC(_provider_with_client(regional_client))

        parsed_vpc = vpc_service.vpcs["vpc-1"]
        assert parsed_vpc.name == "vpc-1"  # falls back to id
        assert parsed_vpc.cidr == ""

        parsed_sg = vpc_service.security_groups["sg-1"]
        assert parsed_sg.name == "sg-1"  # falls back to id
        assert parsed_sg.vpc_id == ""
        parsed_rule = parsed_sg.rules[0]
        assert parsed_rule.protocol == ""
        assert parsed_rule.remote_ip_prefix == ""
        assert parsed_rule.description == ""
        assert parsed_rule.direction == ""

    def test_list_security_groups_empty(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_vpcs.return_value = SimpleNamespace(vpcs=[])
        regional_client.list_security_groups.return_value = SimpleNamespace(
            security_groups=[]
        )

        vpc_service = VPC(_provider_with_client(regional_client))

        assert vpc_service.vpcs == {}
        assert vpc_service.security_groups == {}

    def test_list_security_groups_handles_sdk_error(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_vpcs.side_effect = Exception("boom")
        regional_client.list_security_groups.side_effect = Exception("boom")

        vpc_service = VPC(_provider_with_client(regional_client))

        # Errors are logged and swallowed; no partial/garbage resources.
        assert vpc_service.vpcs == {}
        assert vpc_service.security_groups == {}
