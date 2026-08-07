from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class DNS(HuaweiCloudService):
    """
    DNS service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud DNS service
    to retrieve public DNS zones.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.public_zones: List[PublicZone] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_public_zones()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.public_zones = [
            PublicZone(
                id="zone-mock-001",
                name="example.com.",
                record_num=5,
                status="ACTIVE",
                region=region,
            ),
            PublicZone(
                id="zone-mock-002",
                name="internal.example.com.",
                record_num=10,
                status="ACTIVE",
                region=region,
            ),
        ]

    def _list_public_zones(self):
        """List all public DNS zones across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"DNS - Listing Public Zones in {region}...")

            try:
                from huaweicloudsdkdns.v2 import ListPublicZonesRequest

                request = ListPublicZonesRequest()
                response = self._call_with_retries(client.list_public_zones, request)

                if response and response.zones:
                    for zone in response.zones:
                        self.public_zones.append(
                            PublicZone(
                                id=getattr(zone, "id", ""),
                                name=getattr(zone, "name", ""),
                                record_num=getattr(zone, "record_num", 0) or 0,
                                status=getattr(zone, "status", ""),
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class PublicZone(BaseModel):
    """Public DNS Zone model."""

    id: str
    name: str = ""
    record_num: int = 0
    status: str = ""
    region: str = ""
