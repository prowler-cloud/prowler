from typing import List

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService
from prowler.providers.huaweicloud.models import HuaweiCloudBaseModel


class EVS(HuaweiCloudService):
    """
    EVS (Elastic Volume Service) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud EVS service
    to retrieve disk volumes and their encryption status.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.volumes: List[Volume] = []

        self.__threading_call__(self._list_volumes)

    def _list_volumes(self, regional_client):
        """List all EVS volumes in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"EVS - Listing Volumes in {region}...")

        try:
            from huaweicloudsdkevs.v2 import ListVolumesRequest

            page_size = 1000
            offset = 0
            while True:
                request = ListVolumesRequest(limit=page_size, offset=offset)
                response = self._call_with_retries(
                    regional_client.list_volumes, request
                )
                if not response or not response.volumes:
                    break

                for vol_data in response.volumes:
                    metadata = getattr(vol_data, "metadata", None) or {}
                    is_encrypted = bool(getattr(vol_data, "encrypted", False)) or (
                        metadata.get("__system__encrypted") == "1"
                    )
                    self.volumes.append(
                        Volume(
                            id=getattr(vol_data, "id", "") or "",
                            name=getattr(vol_data, "name", "") or "",
                            is_encrypted=is_encrypted,
                            kms_key_id=metadata.get("__system__cmkid", "") or "",
                            region=region,
                        )
                    )

                if len(response.volumes) < page_size:
                    break
                offset += page_size

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Volume(HuaweiCloudBaseModel):
    """EVS Volume model."""

    id: str
    name: str
    is_encrypted: bool = False
    kms_key_id: str = ""
    region: str = ""
