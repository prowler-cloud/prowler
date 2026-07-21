from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class WAF(HuaweiCloudService):
    """
    WAF (Web Application Firewall) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud WAF service
    to retrieve WAF instances (dedicated and cloud) and their status.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.instances: List[WAFInstance] = []

        self._list_instances()

    def _list_instances(self):
        """List all WAF dedicated instances across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"WAF - Listing Instances in {region}...")

            try:
                from huaweicloudsdkwaf.v1 import ListInstanceRequest

                request = ListInstanceRequest()
                response = self._call_with_retries(client.list_instance, request)

                if response and response.items:
                    for inst_data in response.items:
                        name = (
                            getattr(inst_data, "instancename", "")
                            or getattr(inst_data, "instance_name", "")
                            or ""
                        )
                        self.instances.append(
                            WAFInstance(
                                id=getattr(inst_data, "id", "") or "",
                                name=name,
                                status=getattr(inst_data, "status", 0) or 0,
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class WAFInstance(BaseModel):
    """WAF Instance model."""

    id: str
    name: str
    status: int = 0
    region: str = ""
