from datetime import datetime
from typing import Optional

from alibabacloud_vpc20160428 import models as vpc_models
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


class VPC(AlibabaCloudService):
    """
    VPC (Virtual Private Cloud) service class for Alibaba Cloud.

    This class provides methods to interact with Alibaba Cloud VPC service
    to retrieve VPCs, flow logs, etc.
    """

    def __init__(self, provider):
        # Call AlibabaCloudService's __init__
        super().__init__(__class__.__name__, provider, global_service=False)

        # Fetch VPC resources
        self.vpcs = {}
        self.__threading_call__(self._describe_vpcs)
        self._describe_flow_logs()

    def _describe_vpcs(self, regional_client):
        """List all VPCs in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"VPC - Describing VPCs in {region}...")

        try:
            request = vpc_models.DescribeVpcsRequest()
            response = regional_client.describe_vpcs(request)

            if response and response.body and response.body.vpcs:
                for vpc_data in response.body.vpcs.vpc:
                    if not self.audit_resources or is_resource_filtered(
                        vpc_data.vpc_id, self.audit_resources
                    ):
                        vpc_id = vpc_data.vpc_id
                        self.vpcs[vpc_id] = VPCs(
                            id=vpc_id,
                            name=getattr(vpc_data, "vpc_name", vpc_id),
                            region=region,
                            cidr_block=getattr(vpc_data, "cidr_block", ""),
                            description=getattr(vpc_data, "description", ""),
                            create_time=getattr(vpc_data, "creation_time", None),
                            is_default=getattr(vpc_data, "is_default", False),
                            flow_log_enabled=False,  # Will be updated in _describe_flow_logs
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_flow_logs(self):
        """Get flow logs for all VPCs."""
        logger.info("VPC - Describing Flow Logs...")

        for vpc_id, vpc in self.vpcs.items():
            try:
                regional_client = self.regional_clients.get(vpc.region)
                if not regional_client:
                    continue

                request = vpc_models.DescribeFlowLogsRequest()
                request.resource_id = vpc_id
                request.resource_type = "VPC"
                response = regional_client.describe_flow_logs(request)

                if response and response.body and response.body.flow_logs:
                    flow_logs = response.body.flow_logs.flow_log
                    if flow_logs:
                        # Check if any flow log is active
                        for flow_log in flow_logs:
                            status = getattr(flow_log, "status", "")
                            if status == "Active":
                                vpc.flow_log_enabled = True
                                break

            except Exception as error:
                logger.error(
                    f"{vpc.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


# Models for VPC service
class VPCs(BaseModel):
    """VPC model."""

    id: str
    name: str
    region: str
    cidr_block: str
    description: str = ""
    create_time: Optional[datetime] = None
    is_default: bool = False
    flow_log_enabled: bool = False
