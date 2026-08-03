from typing import List

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService
from prowler.providers.huaweicloud.models import HuaweiCloudBaseModel


class CTS(HuaweiCloudService):
    """
    CTS (Cloud Trace Service) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud CTS service
    to retrieve trackers and their configuration.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.trackers: List[Tracker] = []

        self.__threading_call__(self._list_trackers)

    def _list_trackers(self, regional_client):
        """List all CTS trackers in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"CTS - Listing Trackers in {region}...")

        try:
            from huaweicloudsdkcts.v3 import ListTrackersRequest

            request = ListTrackersRequest()
            response = self._call_with_retries(regional_client.list_trackers, request)

            if response and response.trackers:
                for tracker_data in response.trackers:
                    obs_info = getattr(tracker_data, "obs_info", None)
                    self.trackers.append(
                        Tracker(
                            id=getattr(tracker_data, "id", None) or "",
                            name=getattr(tracker_data, "tracker_name", None) or "",
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


class Tracker(HuaweiCloudBaseModel):
    """CTS Tracker model."""

    id: str
    name: str
    tracker_type: str = ""
    is_enabled: bool = False
    bucket_name: str = ""
    file_prefix_name: str = ""
    region: str = ""
