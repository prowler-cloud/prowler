from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class EVS(HuaweiCloudService):
    """
    EVS (Elastic Volume Service) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud EVS service
    to retrieve disk volumes and their encryption status.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.volumes: List[Volume] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_volumes()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.volumes = [
            Volume(
                id="vol-mock-001", name="encrypted-volume", is_encrypted=True,
                kms_key_id="kms-mock-001", region=region,
            ),
            Volume(
                id="vol-mock-002", name="unencrypted-volume", is_encrypted=False,
                kms_key_id="", region=region,
            ),
            Volume(
                id="vol-mock-003", name="encrypted-volume-2", is_encrypted=True,
                kms_key_id="kms-mock-002", region=region,
            ),
        ]

    def _list_volumes(self):
        """List all EVS volumes across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"EVS - Listing Volumes in {region}...")

            try:
                from huaweicloudsdkevs.v2 import ListVolumesRequest

                request = ListVolumesRequest()
                response = self._call_with_retries(
                    client.list_volumes, request
                )

                if response and response.volumes:
                    for vol_data in response.volumes:
                        self.volumes.append(
                            Volume(
                                id=getattr(vol_data, "id", ""),
                                name=getattr(vol_data, "name", ""),
                                is_encrypted=getattr(vol_data, "encrypted", False),
                                kms_key_id=getattr(vol_data, "metadata", {}).get("__system__cmkid", ""),
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Volume(BaseModel):
    """EVS Volume model."""

    id: str
    name: str
    is_encrypted: bool = False
    kms_key_id: str = ""
    region: str = ""
