from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################## DocumentDB
class DocumentDB(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__("docdb", audit_info)
        self.db_instances = []
        self.__threading_call__(self.__describe_db_instances__)

    def __describe_db_instances__(self, regional_client):
        logger.info("RDS - Describe Instances...")
        try:
            describe_db_instances_paginator = regional_client.get_paginator(
                "describe_db_instances"
            )
            for page in describe_db_instances_paginator.paginate():
                for instance in page["DBInstances"]:
                    self.db_instances.append(
                        DBInstance(
                            id=instance["DBInstanceIdentifier"],
                            endpoint=instance.get("Endpoint"),
                            engine=instance["Engine"],
                            engine_version=instance["EngineVersion"],
                            status=instance["DBInstanceStatus"],
                            public=instance["PubliclyAccessible"],
                            encrypted=instance["StorageEncrypted"],
                            auto_minor_version_upgrade=instance[
                                "AutoMinorVersionUpgrade"
                            ],
                            backup_retention_period=instance.get(
                                "BackupRetentionPeriod"
                            ),
                            cloudwatch_logs=instance.get(
                                "EnabledCloudwatchLogsExports"
                            ),
                            enhanced_monitoring_arn=instance.get(
                                "EnhancedMonitoringResourceArn"
                            ),
                            cluster_id=instance.get("DBClusterIdentifier"),
                            region=regional_client.region,
                            tags=instance.get("TagList", []),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class DBInstance(BaseModel):
    id: str
    endpoint: Optional[dict]
    engine: str
    engine_version: str
    status: str
    public: bool
    encrypted: bool
    backup_retention_period: int = 0
    cloudwatch_logs: Optional[list]
    auto_minor_version_upgrade: bool
    enhanced_monitoring_arn: Optional[str]
    parameters: list[dict] = []
    cluster_id: Optional[str]
    region: str
    tags: Optional[list] = []
