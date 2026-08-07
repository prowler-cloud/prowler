from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class CFW(HuaweiCloudService):
    """
    CFW service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud Cloud Firewall
    service to retrieve firewall instances.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.firewalls: List[Firewall] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_firewalls()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.firewalls = [
            Firewall(
                fw_instance_id="cfw-mock-001",
                name="test-firewall",
                status="1",
                region=region,
            ),
        ]

    def _list_firewalls(self):
        """List all Cloud Firewall instances across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"CFW - Listing Firewalls in {region}...")

            try:
                from huaweicloudsdkcfw.v1 import ListFirewallListRequest

                request = ListFirewallListRequest()
                response = self._call_with_retries(
                    client.list_firewall_list, request
                )

                if response and response.data and response.data.records:
                    for fw in response.data.records:
                        self.firewalls.append(
                            Firewall(
                                fw_instance_id=getattr(fw, "fw_instance_id", ""),
                                name=getattr(fw, "name", "")
                                or getattr(fw, "fw_instance_name", ""),
                                status=getattr(fw, "status", ""),
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Firewall(BaseModel):
    """Cloud Firewall instance model."""

    fw_instance_id: str
    name: str = ""
    status: str = ""
    region: str = ""
