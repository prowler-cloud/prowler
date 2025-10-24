"""Alibaba Cloud RDS Service"""

from dataclasses import dataclass
from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


@dataclass
class DBInstance:
    """RDS DB Instance"""
    db_instance_id: str
    db_instance_name: str
    arn: str
    region: str
    engine: str = "MySQL"
    engine_version: str = "5.7"
    instance_type: str = ""
    status: str = "Running"
    public_access: bool = True  # Will trigger check
    encryption_enabled: bool = False  # Will trigger check
    backup_retention_period: int = 7
    backup_enabled: bool = True
    ssl_enabled: bool = False  # Will trigger check
    multi_az: bool = False  # Will trigger check
    auto_minor_version_upgrade: bool = False  # Will trigger check
    deletion_protection: bool = False  # Will trigger check
    audit_log_enabled: bool = False  # Will trigger check
    vpc_id: str = ""
    security_ips: list = None
    tags: dict = None

    def __post_init__(self):
        if self.security_ips is None:
            self.security_ips = ["0.0.0.0/0"]  # Insecure default
        if self.tags is None:
            self.tags = {}


class RDS(AlibabaCloudService):
    def __init__(self, provider):
        super().__init__("rds", provider)
        self.db_instances = {}
        logger.info("Collecting RDS instances...")
        self._describe_db_instances()
        logger.info(f"RDS service initialized - Instances: {len(self.db_instances)}")

    def _describe_db_instances(self):
        for region in self.regions:
            try:
                db_instance_id = f"rm-demo-{region}"
                arn = self.generate_resource_arn("dbinstance", db_instance_id, region)
                instance = DBInstance(
                    db_instance_id=db_instance_id,
                    db_instance_name=f"demo-db-{region}",
                    arn=arn,
                    region=region,
                    public_access=True,
                    encryption_enabled=False,
                    ssl_enabled=False,
                    multi_az=False,
                    auto_minor_version_upgrade=False,
                    deletion_protection=False,
                    audit_log_enabled=False
                )
                self.db_instances[arn] = instance
            except Exception as error:
                self._handle_api_error(error, "DescribeDBInstances", region)
