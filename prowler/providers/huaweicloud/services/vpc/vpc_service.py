from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


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
                        self.vpcs[vpc_id] = VPCs(
                            id=vpc_id,
                            name=getattr(vpc_data, "name", vpc_id),
                            region=region,
                            cidr=getattr(vpc_data, "cidr", ""),
                            status=getattr(vpc_data, "status", ""),
                            description=getattr(vpc_data, "description", ""),
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
                                rules.append(
                                    SecurityGroupRule(
                                        id=rule_data.id,
                                        direction=getattr(rule_data, "direction", ""),
                                        protocol=getattr(rule_data, "protocol", ""),
                                        ethertype=getattr(rule_data, "ethertype", ""),
                                        port_range_min=getattr(
                                            rule_data, "port_range_min", None
                                        ),
                                        port_range_max=getattr(
                                            rule_data, "port_range_max", None
                                        ),
                                        remote_ip_prefix=getattr(
                                            rule_data, "remote_ip_prefix", ""
                                        ),
                                        remote_group_id=getattr(
                                            rule_data, "remote_group_id", ""
                                        ),
                                        description=getattr(
                                            rule_data, "description", ""
                                        ),
                                    )
                                )

                        self.security_groups[sg_id] = SecurityGroups(
                            id=sg_id,
                            name=getattr(sg_data, "name", sg_id),
                            region=region,
                            vpc_id=getattr(sg_data, "vpc_id", ""),
                            description=getattr(sg_data, "description", ""),
                            rules=rules,
                        )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class VPCs(BaseModel):
    """VPC model."""

    id: str
    name: str
    region: str
    cidr: str
    status: str = ""
    description: str = ""
    created_at: Optional[str] = None


class SecurityGroupRule(BaseModel):
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


class SecurityGroups(BaseModel):
    """Security Group model."""

    id: str
    name: str
    region: str
    vpc_id: str = ""
    description: str = ""
    rules: List[SecurityGroupRule] = []
