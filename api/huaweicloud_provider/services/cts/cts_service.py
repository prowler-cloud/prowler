from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class CTS(HuaweiCloudService):
    """
    CTS (Cloud Trace Service) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud CTS service
    to retrieve trackers and their configuration.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=True)

        self.trackers: List[Tracker] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_trackers()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.trackers = [
            Tracker(
                id="cts-tracker-001", name="system-tracker", tracker_type="system",
                is_enabled=True, bucket_name="cts-bucket-001", region=region,
            ),
            Tracker(
                id="cts-tracker-002", name="custom-tracker-disabled", tracker_type="data",
                is_enabled=False, bucket_name="cts-bucket-002", region=region,
            ),
        ]

    def _list_trackers(self):
        """List all CTS trackers."""
        if not self.regional_clients:
            return

        region = list(self.regional_clients.keys())[0]
        client = self.regional_clients[region]
        logger.info(f"CTS - Listing Trackers in {region}...")

        try:
            from huaweicloudsdkcts.v3 import ListTrackersRequest

            request = ListTrackersRequest()
            response = self._call_with_retries(
                client.list_trackers, request
            )

            if response and response.trackers:
                for tracker_data in response.trackers:
                    self.trackers.append(
                        Tracker(
                            id=getattr(tracker_data, "id", ""),
                            name=getattr(tracker_data, "tracker_name", ""),
                            tracker_type=getattr(tracker_data, "tracker_type", ""),
                            is_enabled=getattr(tracker_data, "is_support_validation", False),
                            bucket_name=getattr(tracker_data, "bucket_name", ""),
                            file_prefix_name=getattr(tracker_data, "file_prefix_name", ""),
                            region=region,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Tracker(BaseModel):
    """CTS Tracker model."""

    id: str
    name: str
    tracker_type: str = ""
    is_enabled: bool = False
    bucket_name: str = ""
    file_prefix_name: str = ""
    region: str = ""
