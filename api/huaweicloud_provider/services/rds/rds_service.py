from typing import List, Optional

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

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_instances()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.instances = [
            RDSInstance(
                id="rds-mock-001", name="public-db-with-backup", status="ACTIVE",
                engine="mysql", engine_version="8.0", public_ip="123.45.67.200",
                is_public=True, backup_enabled=True, region=region,
                disk_encryption_id="kms-mock-001",
            ),
            RDSInstance(
                id="rds-mock-002", name="private-db-no-backup", status="ACTIVE",
                engine="postgresql", engine_version="14", public_ip="",
                is_public=False, backup_enabled=False, region=region,
                disk_encryption_id="",
            ),
            RDSInstance(
                id="rds-mock-003", name="private-db-with-backup", status="ACTIVE",
                engine="mysql", engine_version="8.0", public_ip="",
                is_public=False, backup_enabled=True, region=region,
                disk_encryption_id="kms-mock-002",
            ),
        ]

    def _list_instances(self):
        """List all RDS instances across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"RDS - Listing Instances in {region}...")

            try:
                from huaweicloudsdkrds.v3 import ListInstancesRequest

                request = ListInstancesRequest()
                response = self._call_with_retries(
                    client.list_instances, request
                )

                if response and response.instances:
                    for inst_data in response.instances:
                        public_ip = ""
                        if getattr(inst_data, "public_ip", None):
                            public_ip = inst_data.public_ip

                        is_public = bool(public_ip and public_ip.strip())

                        backup_enabled = False
                        backup_strategy = getattr(inst_data, "backup_strategy", None)
                        if backup_strategy:
                            keep_days = getattr(backup_strategy, "keep_days", 0)
                            if keep_days and keep_days > 0:
                                backup_enabled = True

                        datastore = getattr(inst_data, "datastore", None)
                        engine = getattr(datastore, "type", "") if datastore else ""
                        engine_version = getattr(datastore, "version", "") if datastore else ""

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
                                disk_encryption_id=getattr(inst_data, "disk_encryption_id", ""),
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
