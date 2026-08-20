from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class LTS(HuaweiCloudService):
    """
    LTS (Log Tank Service) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud LTS service
    to retrieve log groups and their retention settings.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.log_groups: List[LTSLogGroup] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_log_groups()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.log_groups = [
            LTSLogGroup(
                log_group_id="group-001",
                log_group_name="app-logs",
                ttl_in_days=30,
                region=region,
            ),
            LTSLogGroup(
                log_group_id="group-002",
                log_group_name="short-retention-logs",
                ttl_in_days=7,
                region=region,
            ),
        ]

    def _list_log_groups(self):
        """List all LTS log groups across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"LTS - Listing Log Groups in {region}...")

            try:
                from huaweicloudsdklts.v2 import ListLogGroupsRequest

                request = ListLogGroupsRequest()
                response = self._call_with_retries(client.list_log_groups, request)

                if response and response.log_groups:
                    for group in response.log_groups:
                        log_group_id = getattr(group, "log_group_id", "") or ""
                        log_group_name = getattr(group, "log_group_name", "") or ""
                        ttl_in_days = getattr(group, "ttl_in_days", None)

                        self.log_groups.append(
                            LTSLogGroup(
                                log_group_id=log_group_id,
                                log_group_name=log_group_name,
                                ttl_in_days=ttl_in_days,
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class LTSLogGroup(BaseModel):
    """LTS log group model."""

    log_group_id: str
    log_group_name: str = ""
    ttl_in_days: int = None
    region: str = ""
