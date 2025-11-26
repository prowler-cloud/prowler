from datetime import datetime
from typing import Optional

from alibabacloud_actiontrail20200706 import models as actiontrail_models
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


class ActionTrail(AlibabaCloudService):
    """
    ActionTrail service class for Alibaba Cloud.

    This class provides methods to interact with Alibaba Cloud ActionTrail service
    to retrieve trails and their configuration.
    """

    def __init__(self, provider):
        # Call AlibabaCloudService's __init__
        # ActionTrail is a regional service
        super().__init__(__class__.__name__, provider, global_service=False)

        # Fetch ActionTrail resources
        self.trails = {}
        self.__threading_call__(self._describe_trails)

    def _describe_trails(self, regional_client):
        """List all ActionTrail trails."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"ActionTrail - Describing trails in {region}...")
        try:
            # Use Tea SDK client (ActionTrail is regional service)
            request = actiontrail_models.DescribeTrailsRequest()
            response = regional_client.describe_trails(request)

            if response and response.body and response.body.trail_list:
                # trail_list is already a list, not an object with a trail attribute
                trails_list = response.body.trail_list
                if not isinstance(trails_list, list):
                    trails_list = [trails_list]

                for trail_data in trails_list:
                    trail_name = getattr(trail_data, "name", "")
                    if not trail_name:
                        continue

                    # Get trail region (can be specific region or "All")
                    trail_region = getattr(trail_data, "trail_region", "")
                    home_region = getattr(trail_data, "home_region", "")
                    status = getattr(trail_data, "status", "")

                    # Create ARN
                    arn = f"acs:actiontrail::{self.audited_account}:trail/{trail_name}"

                    if not self.audit_resources or is_resource_filtered(
                        arn, self.audit_resources
                    ):
                        # Parse creation date if available
                        creation_date = None
                        creation_date_str = getattr(trail_data, "create_time", None)
                        if creation_date_str:
                            try:
                                # ActionTrail date format: "2024-02-02T10:02:11Z" or similar
                                creation_date = datetime.strptime(
                                    creation_date_str.replace("Z", "+00:00"),
                                    "%Y-%m-%dT%H:%M:%S%z",
                                )
                            except (ValueError, AttributeError):
                                creation_date = datetime.strptime(
                                    creation_date_str.replace("Z", "+00:00"),
                                    "%Y-%m-%dT%H:%M:%S.%f%z",
                                )

                        self.trails[arn] = Trail(
                            arn=arn,
                            name=trail_name,
                            home_region=home_region,
                            trail_region=trail_region,
                            status=status,
                            oss_bucket_name=getattr(trail_data, "oss_bucket_name", ""),
                            oss_bucket_location=getattr(
                                trail_data, "oss_bucket_location", ""
                            ),
                            sls_project_arn=getattr(trail_data, "sls_project_arn", ""),
                            event_rw=getattr(trail_data, "event_rw", ""),
                            creation_date=creation_date,
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Service Models
class Trail(BaseModel):
    """ActionTrail Trail model."""

    arn: str
    name: str
    home_region: str
    trail_region: str  # "All" for multi-region, or specific region name
    status: str  # "Enable" or "Disable"
    oss_bucket_name: str = ""
    oss_bucket_location: str = ""
    sls_project_arn: str = ""
    event_rw: str = ""  # "All", "Read", "Write"
    creation_date: Optional[datetime] = None
