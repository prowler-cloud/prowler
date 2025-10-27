"""
Alibaba Cloud ActionTrail Service

This module provides the service class for Alibaba Cloud ActionTrail.
"""

from dataclasses import dataclass

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

        logger.info(f"ActionTrail service initialized - Trails: {len(self.trails)}")

    def _describe_trails(self):
        """Describe all ActionTrail trails"""
        # ActionTrail is a global service, but we'll check it once
        try:
            from alibabacloud_actiontrail20200706 import models
            from alibabacloud_actiontrail20200706.client import (
                Client as ActionTrailClient,
            )
            from alibabacloud_tea_openapi import models as openapi_models

            # Create client configuration (use cn-hangzhou as default region)
            config = openapi_models.Config(
                access_key_id=self.provider.session.credentials.access_key_id,
                access_key_secret=self.provider.session.credentials.access_key_secret,
                region_id="cn-hangzhou",
            )

            if self.provider.session.credentials.security_token:
                config.security_token = self.provider.session.credentials.security_token

            # Create ActionTrail client
            client = ActionTrailClient(config)

            # List trails
            request = models.ListTrailsRequest()
            response = client.list_trails(request)

            # Process trails
            if response.body.trails:
                for trail_data in response.body.trails:
                    trail_name = trail_data.name if trail_data.name else "unknown"
                    arn = self.generate_resource_arn("trail", trail_name, "")

                    # Get trail status
                    try:
                        status_request = models.GetTrailStatusRequest(name=trail_name)
                        status_response = client.get_trail_status(status_request)
                        status = (
                            "Enabled" if status_response.body.is_logging else "Disabled"
                        )
                    except Exception:
                        status = "Unknown"

                    trail = Trail(
                        name=trail_name,
                        arn=arn,
                        region="global",
                        status=status,
                        oss_bucket_name=(
                            trail_data.oss_bucket_name
                            if hasattr(trail_data, "oss_bucket_name")
                            else ""
                        ),
                        oss_key_prefix=(
                            trail_data.oss_key_prefix
                            if hasattr(trail_data, "oss_key_prefix")
                            else ""
                        ),
                        sls_project_arn=(
                            trail_data.sls_project_arn
                            if hasattr(trail_data, "sls_project_arn")
                            else ""
                        ),
                        sls_write_role_arn=(
                            trail_data.sls_write_role_arn
                            if hasattr(trail_data, "sls_write_role_arn")
                            else ""
                        ),
                        event_rw=(
                            trail_data.event_rw
                            if hasattr(trail_data, "event_rw")
                            else "Write"
                        ),
                        trail_region=(
                            trail_data.trail_region
                            if hasattr(trail_data, "trail_region")
                            else "All"
                        ),
                        is_organization_trail=(
                            trail_data.is_organization_trail
                            if hasattr(trail_data, "is_organization_trail")
                            else False
                        ),
                        mns_topic_arn=(
                            trail_data.mns_topic_arn
                            if hasattr(trail_data, "mns_topic_arn")
                            else ""
                        ),
                    )

                    self.trails[arn] = trail
                    logger.info(f"Found ActionTrail trail: {trail_name}")
            else:
                logger.info("No ActionTrail trails found")

        except Exception as error:
            self._handle_api_error(error, "DescribeTrails", "global")
