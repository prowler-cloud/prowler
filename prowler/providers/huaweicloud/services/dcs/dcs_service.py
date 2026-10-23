from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class DCS(HuaweiCloudService):
    """
    DCS (Distributed Cache Service) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud DCS service
    to retrieve Redis instances and their security configuration.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.instances: List[DCSInstance] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_instances()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.instances = [
            DCSInstance(
                instance_id="dcs-mock-001",
                name="redis-secure",
                status="RUNNING",
                engine="Redis",
                no_password_access="false",
                publicip_address=None,
                enable_ssl=True,
                region=region,
            ),
            DCSInstance(
                instance_id="dcs-mock-002",
                name="redis-insecure",
                status="RUNNING",
                engine="Redis",
                no_password_access="true",
                publicip_address="1.2.3.4",
                enable_ssl=False,
                region=region,
            ),
        ]

    def _list_instances(self):
        """List all DCS instances across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"DCS - Listing Instances in {region}...")

            try:
                from huaweicloudsdkdcs.v2 import ListInstancesRequest

                request = ListInstancesRequest()
                response = self._call_with_retries(client.list_instances, request)

                if response and response.instances:
                    for inst in response.instances:
                        self.instances.append(
                            DCSInstance(
                                instance_id=getattr(inst, "instance_id", ""),
                                name=getattr(inst, "name", ""),
                                status=getattr(inst, "status", ""),
                                engine=getattr(inst, "engine", ""),
                                no_password_access=getattr(
                                    inst, "no_password_access", None
                                ),
                                publicip_address=getattr(
                                    inst, "publicip_address", None
                                ),
                                enable_ssl=getattr(inst, "enable_ssl", None),
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class DCSInstance(BaseModel):
    """DCS instance model."""

    instance_id: str
    name: str = ""
    status: str = ""
    engine: str = ""
    no_password_access: Optional[str] = None
    publicip_address: Optional[str] = None
    enable_ssl: Optional[bool] = None
    region: str = ""
