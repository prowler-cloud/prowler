from typing import List, Optional

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService
from prowler.providers.huaweicloud.models import HuaweiCloudBaseModel


class VPC(HuaweiCloudService):
    """
    VPC (Virtual Private Cloud) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud VPC service
    to retrieve VPCs, security groups, and their rules.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=False)

        self.vpcs = {}
        self.security_groups = {}

        self.__threading_call__(self._list_vpcs)
        self.__threading_call__(self._list_security_groups)

    def _list_vpcs(self, regional_client):
        """List all VPCs in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"VPC - Listing VPCs in {region}...")

        try:
            from huaweicloudsdkvpc.v2 import ListVpcsRequest

            request = ListVpcsRequest()
            response = self._call_with_retries(regional_client.list_vpcs, request)

            if response and response.vpcs:
                for vpc_data in response.vpcs:
                    if not self.audit_resources or is_resource_filtered(
                        vpc_data.id, self.audit_resources
                    ):
                        vpc_id = vpc_data.id
                        # The SDK returns attributes explicitly set to None, so
                        # `getattr(..., default)` alone is not enough; coerce
                        # None to the field default with `or`.
                        self.vpcs[vpc_id] = VPCs(
                            id=vpc_id,
                            name=getattr(vpc_data, "name", None) or vpc_id,
                            region=region,
                            cidr=getattr(vpc_data, "cidr", None) or "",
                            status=getattr(vpc_data, "status", None) or "",
                            description=getattr(vpc_data, "description", None) or "",
                            created_at=getattr(vpc_data, "created_at", None),
                        )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_security_groups(self, regional_client):
        """List all security groups and their rules in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"VPC - Listing Security Groups in {region}...")

        try:
            from huaweicloudsdkvpc.v2 import ListSecurityGroupsRequest

            request = ListSecurityGroupsRequest()
            response = self._call_with_retries(
                regional_client.list_security_groups, request
            )

            if response and response.security_groups:
                for sg_data in response.security_groups:
                    if not self.audit_resources or is_resource_filtered(
                        sg_data.id, self.audit_resources
                    ):
                        sg_id = sg_data.id
                        rules = []
                        if (
                            hasattr(sg_data, "security_group_rules")
                            and sg_data.security_group_rules
                        ):
                            for rule_data in sg_data.security_group_rules:
                                # The SDK sets optional fields (protocol,
                                # remote_ip_prefix, description, ...) to None;
                                # coerce to the field default with `or`.
                                rules.append(
                                    SecurityGroupRule(
                                        id=getattr(rule_data, "id", None) or "",
                                        direction=getattr(rule_data, "direction", None)
                                        or "",
                                        protocol=getattr(rule_data, "protocol", None)
                                        or "",
                                        ethertype=getattr(rule_data, "ethertype", None)
                                        or "",
                                        port_range_min=getattr(
                                            rule_data, "port_range_min", None
                                        ),
                                        port_range_max=getattr(
                                            rule_data, "port_range_max", None
                                        ),
                                        remote_ip_prefix=getattr(
                                            rule_data, "remote_ip_prefix", None
                                        )
                                        or "",
                                        remote_group_id=getattr(
                                            rule_data, "remote_group_id", None
                                        )
                                        or "",
                                        description=getattr(
                                            rule_data, "description", None
                                        )
                                        or "",
                                    )
                                )

                        self.security_groups[sg_id] = SecurityGroups(
                            id=sg_id,
                            name=getattr(sg_data, "name", None) or sg_id,
                            region=region,
                            vpc_id=getattr(sg_data, "vpc_id", None) or "",
                            description=getattr(sg_data, "description", None) or "",
                            rules=rules,
                        )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class VPCs(HuaweiCloudBaseModel):
    """VPC model."""

    id: str
    name: str
    region: str
    cidr: str
    status: str = ""
    description: str = ""
    created_at: Optional[str] = None


class SecurityGroupRule(HuaweiCloudBaseModel):
    """Security Group Rule model."""

    id: str
    direction: str
    protocol: str
    ethertype: str
    port_range_min: Optional[int] = None
    port_range_max: Optional[int] = None
    remote_ip_prefix: str = ""
    remote_group_id: str = ""
    description: str = ""


class SecurityGroups(HuaweiCloudBaseModel):
    """Security Group model."""

    id: str
    name: str
    region: str
    vpc_id: str = ""
    description: str = ""
    rules: List[SecurityGroupRule] = []


# Names Huawei Cloud uses for the auto-created default security group. It is
# "default" on China/International and "Sys-default" on Europe.
DEFAULT_SECURITY_GROUP_NAMES = ("default", "Sys-default")

# Ports flagged as sensitive when open from the internet.
SENSITIVE_PORTS = frozenset({22, 3389, 3306, 6379, 27017})


def rule_source_is_open(rule: SecurityGroupRule) -> bool:
    """True when a rule allows traffic from any source.

    Huawei Cloud represents "any source" in two ways: an explicit ``0.0.0.0/0``
    (or ``::/0``) in ``remote_ip_prefix``, or leaving both ``remote_ip_prefix``
    and ``remote_group_id`` empty. Rules that reference another security group
    via ``remote_group_id`` are NOT open even when ``remote_ip_prefix`` is
    empty.
    """
    if rule.remote_ip_prefix in ("0.0.0.0/0", "::/0"):
        return True
    return not rule.remote_ip_prefix and not rule.remote_group_id


def rule_covers_all_ports(rule: SecurityGroupRule) -> bool:
    """True when a rule effectively opens every TCP/UDP port.

    Huawei encodes "all ports" as both port_range_min and port_range_max being
    None. A range that spans the full 1-65535 window is equivalent.
    """
    if rule.port_range_min is None and rule.port_range_max is None:
        return True
    return rule.port_range_min == 1 and rule.port_range_max == 65535


def rule_covers_port(rule: SecurityGroupRule, port: int) -> bool:
    """True when the port is inside the rule's port range (all-ports included)."""
    if rule_covers_all_ports(rule):
        return True
    if rule.port_range_min is None:
        return False
    upper = (
        rule.port_range_max if rule.port_range_max is not None else rule.port_range_min
    )
    return rule.port_range_min <= port <= upper
