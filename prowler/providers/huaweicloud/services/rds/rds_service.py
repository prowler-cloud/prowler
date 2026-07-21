from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class RDS(HuaweiCloudService):
    """
    RDS (Relational Database Service) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud RDS service
    to retrieve database instances and their configuration.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.instances: List[RDSInstance] = []

        self._list_instances()

    def _list_instances(self):
        """List all RDS instances across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"RDS - Listing Instances in {region}...")

            try:
                from huaweicloudsdkrds.v3 import ListInstancesRequest

                request = ListInstancesRequest()
                response = self._call_with_retries(client.list_instances, request)

                if response and response.instances:
                    for inst_data in response.instances:
                        public_ips = getattr(inst_data, "public_ips", None) or []
                        public_ips = [ip for ip in public_ips if ip and ip.strip()]
                        public_ip = ", ".join(public_ips)

                        is_public = bool(public_ips)

                        backup_enabled = False
                        backup_strategy = getattr(inst_data, "backup_strategy", None)
                        if backup_strategy:
                            keep_days = getattr(backup_strategy, "keep_days", 0)
                            if keep_days and keep_days > 0:
                                backup_enabled = True

                        datastore = getattr(inst_data, "datastore", None)
                        engine = getattr(datastore, "type", "") if datastore else ""
                        engine_version = (
                            getattr(datastore, "version", "") if datastore else ""
                        )

                        self.instances.append(
                            RDSInstance(
                                id=getattr(inst_data, "id", ""),
                                name=getattr(inst_data, "name", ""),
                                status=getattr(inst_data, "status", ""),
                                engine=engine,
                                engine_version=engine_version,
                                public_ip=public_ip,
                                is_public=is_public,
                                backup_enabled=backup_enabled,
                                region=region,
                                disk_encryption_id=getattr(
                                    inst_data, "disk_encryption_id", ""
                                ),
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class RDSInstance(BaseModel):
    """RDS Instance model."""

    id: str
    name: str
    status: str = ""
    engine: str = ""
    engine_version: str = ""
    public_ip: str = ""
    is_public: bool = False
    backup_enabled: bool = False
    region: str = ""
    disk_encryption_id: str = ""
