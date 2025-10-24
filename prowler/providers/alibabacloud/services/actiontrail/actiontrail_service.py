"""
Alibaba Cloud ActionTrail Service

This module provides the service class for Alibaba Cloud ActionTrail.
"""

from dataclasses import dataclass
from typing import Optional

from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


@dataclass
class Trail:
    """ActionTrail Trail"""
    name: str
    arn: str
    region: str
    status: str = "Disabled"  # Will trigger check
    oss_bucket_name: str = ""
    oss_key_prefix: str = ""
    sls_project_arn: str = ""
    sls_write_role_arn: str = ""
    event_rw: str = "Write"  # Should be "All"
    trail_region: str = "All"
    is_organization_trail: bool = False
    mns_topic_arn: str = ""

    def __post_init__(self):
        pass


class ActionTrail(AlibabaCloudService):
    """
    Alibaba Cloud ActionTrail service class

    Handles collection of ActionTrail resources including trails and their configurations.
    """

    def __init__(self, provider):
        """Initialize ActionTrail service"""
        super().__init__("actiontrail", provider)

        self.trails = {}

        logger.info("Collecting ActionTrail trails...")
        self._describe_trails()

        logger.info(
            f"ActionTrail service initialized - Trails: {len(self.trails)}"
        )

    def _describe_trails(self):
        """Describe all ActionTrail trails"""
        # ActionTrail is a global service, but we'll check it once
        try:
            # TODO: Implement actual SDK call
            # Placeholder: Create sample trail for demonstration
            trail_name = "prowler-demo-trail"
            arn = self.generate_resource_arn("trail", trail_name, "")

            trail = Trail(
                name=trail_name,
                arn=arn,
                region="global",
                status="Disabled",  # Should be "Enabled"
                oss_bucket_name="audit-logs-bucket",
                event_rw="Write",  # Should be "All" to log both read and write
                trail_region="All",
                is_organization_trail=False
            )

            self.trails[arn] = trail

        except Exception as error:
            self._handle_api_error(error, "DescribeTrails", "global")
