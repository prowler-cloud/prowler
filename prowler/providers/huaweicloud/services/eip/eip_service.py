from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class EIP(HuaweiCloudService):
    """
    EIP (Elastic IP) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud EIP service
    to retrieve public IP addresses and their association status.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.public_ips: List[PublicIP] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_public_ips()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.public_ips = [
            PublicIP(
                id="eip-mock-001",
                public_ip_address="1.2.3.4",
                status="ACTIVE",
                port_id="port-001",
                region=region,
            ),
            PublicIP(
                id="eip-mock-002",
                public_ip_address="5.6.7.8",
                status="DOWN",
                port_id=None,
                region=region,
            ),
        ]

    def _list_public_ips(self):
        """List all public IPs across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"EIP - Listing Public IPs in {region}...")

            try:
                from huaweicloudsdkeip.v2 import ListPublicipsRequest

                request = ListPublicipsRequest()
                response = self._call_with_retries(
                    client.list_publicips, request
                )

                if response and response.publicips:
                    for eip_data in response.publicips:
                        self.public_ips.append(
                            PublicIP(
                                id=getattr(eip_data, "id", ""),
                                public_ip_address=getattr(eip_data, "public_ip_address", ""),
                                status=getattr(eip_data, "status", ""),
                                port_id=getattr(eip_data, "port_id", None),
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class PublicIP(BaseModel):
    """Public IP model."""

    id: str
    public_ip_address: str = ""
    status: str = ""
    port_id: Optional[str] = None
    region: str = ""
