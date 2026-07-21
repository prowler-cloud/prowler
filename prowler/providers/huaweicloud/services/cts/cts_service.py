from typing import List

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

        self._list_trackers()

    def _list_trackers(self):
        """List all CTS trackers."""
        if not self.client:
            return

        region = self.region
        client = self.client
        logger.info(f"CTS - Listing Trackers in {region}...")

        try:
            from huaweicloudsdkcts.v3 import ListTrackersRequest

            request = ListTrackersRequest()
            response = self._call_with_retries(client.list_trackers, request)

            if response and response.trackers:
                for tracker_data in response.trackers:
                    obs_info = getattr(tracker_data, "obs_info", None)
                    self.trackers.append(
                        Tracker(
                            id=getattr(tracker_data, "id", ""),
                            name=getattr(tracker_data, "tracker_name", ""),
                            tracker_type=getattr(tracker_data, "tracker_type", ""),
                            is_enabled=getattr(tracker_data, "status", "") == "enabled",
                            bucket_name=(
                                getattr(obs_info, "bucket_name", "") if obs_info else ""
                            ),
                            file_prefix_name=(
                                getattr(obs_info, "file_prefix_name", "")
                                if obs_info
                                else ""
                            ),
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
