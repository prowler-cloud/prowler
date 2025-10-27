"""
Alibaba Cloud VPC Service

This module provides the service class for Alibaba Cloud Virtual Private Cloud (VPC).
"""

from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


@dataclass
class VPC:
    """VPC"""

    vpc_id: str
    vpc_name: str
    arn: str
    region: str
    cidr_block: str = ""
    status: str = ""
    is_default: bool = False
    creation_time: str = ""

    def __post_init__(self):
        pass


@dataclass
class VSwitch:
    """VSwitch (Subnet)"""

    vswitch_id: str
    vswitch_name: str
    arn: str
    region: str
    vpc_id: str = ""
    zone_id: str = ""
    cidr_block: str = ""
    available_ip_count: int = 0
    status: str = ""

    def __post_init__(self):
        pass


@dataclass
class FlowLog:
    """VPC Flow Log"""

    flow_log_id: str
    flow_log_name: str
    arn: str
    region: str
    resource_type: str = ""  # VPC or VSwitch
    resource_id: str = ""
    traffic_type: str = "All"
    project_name: str = ""
    log_store_name: str = ""
    status: str = ""

    def __post_init__(self):
        pass


@dataclass
class NetworkACL:
    """Network ACL"""

    network_acl_id: str
    network_acl_name: str
    arn: str
    region: str
    vpc_id: str = ""
    status: str = ""
    ingress_rules: list = None
    egress_rules: list = None

    def __post_init__(self):
        if self.ingress_rules is None:
            self.ingress_rules = []
        if self.egress_rules is None:
            self.egress_rules = []


class VPC_Service(AlibabaCloudService):
    """
    Alibaba Cloud VPC service class

    Handles collection of VPC resources including VPCs, VSwitches, Flow Logs, and Network ACLs.
    """

    def __init__(self, provider):
        """Initialize VPC service"""
        super().__init__("vpc", provider)

        self.vpcs = {}
        self.vswitches = {}
        self.flow_logs = {}
        self.network_acls = {}

        logger.info("Collecting VPCs...")
        self._describe_vpcs()

        logger.info("Collecting VPC Flow Logs...")
        self._describe_flow_logs()

        logger.info(
            f"VPC service initialized - VPCs: {len(self.vpcs)}, Flow Logs: {len(self.flow_logs)}"
        )

    def _describe_vpcs(self):
        """Describe all VPCs"""
        for region in self.regions:
            try:
                from alibabacloud_tea_openapi import models as openapi_models
                from alibabacloud_vpc20160428 import models
                from alibabacloud_vpc20160428.client import Client as VpcClient

                # Create client configuration
                config = openapi_models.Config(
                    access_key_id=self.provider.session.credentials.access_key_id,
                    access_key_secret=self.provider.session.credentials.access_key_secret,
                    region_id=region,
                )

                if self.provider.session.credentials.security_token:
                    config.security_token = (
                        self.provider.session.credentials.security_token
                    )

                # Create VPC client
                client = VpcClient(config)

                # Describe VPCs
                request = models.DescribeVpcsRequest(page_size=50, region_id=region)
                response = client.describe_vpcs(request)

                # Process VPCs
                if response.body.vpcs and response.body.vpcs.vpc:
                    for vpc_data in response.body.vpcs.vpc:
                        vpc_id = vpc_data.vpc_id
                        arn = self.generate_resource_arn("vpc", vpc_id, region)

                        vpc = VPC(
                            vpc_id=vpc_id,
                            vpc_name=vpc_data.vpc_name if vpc_data.vpc_name else vpc_id,
                            arn=arn,
                            region=region,
                            cidr_block=(
                                vpc_data.cidr_block if vpc_data.cidr_block else ""
                            ),
                            status=vpc_data.status if vpc_data.status else "",
                            is_default=(
                                vpc_data.is_default
                                if hasattr(vpc_data, "is_default")
                                else False
                            ),
                            creation_time=(
                                vpc_data.creation_time if vpc_data.creation_time else ""
                            ),
                        )

                        self.vpcs[arn] = vpc
                        logger.info(f"Found VPC: {vpc_id} in {region}")
                else:
                    logger.info(f"No VPCs found in {region}")

            except Exception as error:
                self._handle_api_error(error, "DescribeVpcs", region)

    def _describe_flow_logs(self):
        """Describe all VPC Flow Logs"""
        for region in self.regions:
            try:
                from alibabacloud_tea_openapi import models as openapi_models
                from alibabacloud_vpc20160428 import models
                from alibabacloud_vpc20160428.client import Client as VpcClient

                # Create client configuration
                config = openapi_models.Config(
                    access_key_id=self.provider.session.credentials.access_key_id,
                    access_key_secret=self.provider.session.credentials.access_key_secret,
                    region_id=region,
                )

                if self.provider.session.credentials.security_token:
                    config.security_token = (
                        self.provider.session.credentials.security_token
                    )

                # Create VPC client
                client = VpcClient(config)

                # Describe Flow Logs
                request = models.DescribeFlowLogsRequest(page_size=50, region_id=region)
                response = client.describe_flow_logs(request)

                # Process Flow Logs
                if response.body.flow_logs and response.body.flow_logs.flow_log:
                    for flow_log_data in response.body.flow_logs.flow_log:
                        flow_log_id = flow_log_data.flow_log_id
                        arn = self.generate_resource_arn("flowlog", flow_log_id, region)

                        flow_log = FlowLog(
                            flow_log_id=flow_log_id,
                            flow_log_name=(
                                flow_log_data.flow_log_name
                                if flow_log_data.flow_log_name
                                else flow_log_id
                            ),
                            arn=arn,
                            region=region,
                            resource_type=(
                                flow_log_data.resource_type
                                if hasattr(flow_log_data, "resource_type")
                                else ""
                            ),
                            resource_id=(
                                flow_log_data.resource_id
                                if hasattr(flow_log_data, "resource_id")
                                else ""
                            ),
                            traffic_type=(
                                flow_log_data.traffic_type
                                if hasattr(flow_log_data, "traffic_type")
                                else "All"
                            ),
                            project_name=(
                                flow_log_data.project_name
                                if hasattr(flow_log_data, "project_name")
                                else ""
                            ),
                            log_store_name=(
                                flow_log_data.log_store_name
                                if hasattr(flow_log_data, "log_store_name")
                                else ""
                            ),
                            status=flow_log_data.status if flow_log_data.status else "",
                        )

                        self.flow_logs[arn] = flow_log
                        logger.info(f"Found Flow Log: {flow_log_id} in {region}")
                else:
                    logger.info(f"No Flow Logs found in {region}")

            except Exception as error:
                self._handle_api_error(error, "DescribeFlowLogs", region)
