import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## RDS
class RDS:
    def __init__(self, audit_info):
        self.service = "rds"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.db_instances = []
        self.db_snapshots = []
        self.db_cluster_snapshots = []
        self.__threading_call__(self.__describe_db_instances__)
        self.__threading_call__(self.__describe_db_snapshots__)
        self.__threading_call__(self.__describe_db_snapshot_attributes__)
        self.__threading_call__(self.__describe_db_cluster_snapshots__)
        self.__threading_call__(self.__describe_db_cluster_snapshot_attributes__)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __describe_db_instances__(self, regional_client):
        logger.info("RDS - Describe Instances...")
        try:
            describe_db_instances_paginator = regional_client.get_paginator(
                "describe_db_instances"
            )
            for page in describe_db_instances_paginator.paginate():
                for instance in page["DBInstances"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            instance["DBInstanceIdentifier"], self.audit_resources
                        )
                    ):
                        if instance["Engine"] != "docdb":
                            self.db_instances.append(
                                DBInstance(
                                    id=instance["DBInstanceIdentifier"],
                                    endpoint=instance.get("Endpoint"),
                                    engine=instance["Engine"],
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
                                    deletion_protection=instance["DeletionProtection"],
                                    enhanced_monitoring_arn=instance.get(
                                        "EnhancedMonitoringResourceArn"
                                    ),
                                    multi_az=instance["MultiAZ"],
                                    region=regional_client.region,
                                    tags=instance.get("TagList"),
                                )
                            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_db_snapshots__(self, regional_client):
        logger.info("RDS - Describe Snapshots...")
        try:
            describe_db_snapshots_paginator = regional_client.get_paginator(
                "describe_db_snapshots"
            )
            for page in describe_db_snapshots_paginator.paginate():
                for snapshot in page["DBSnapshots"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            snapshot["DBSnapshotIdentifier"], self.audit_resources
                        )
                    ):
                        if snapshot["Engine"] != "docdb":
                            print(snapshot)
                            self.db_snapshots.append(
                                DBSnapshot(
                                    id=snapshot["DBSnapshotIdentifier"],
                                    instance_id=snapshot["DBInstanceIdentifier"],
                                    region=regional_client.region,
                                    tags=snapshot.get("TagList"),
                                )
                            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_db_snapshot_attributes__(self, regional_client):
        logger.info("RDS - Describe Snapshot Attributes...")
        try:
            for snapshot in self.db_snapshots:
                if snapshot.region == regional_client.region:
                    response = regional_client.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=snapshot.id
                    )["DBSnapshotAttributesResult"]
                    for att in response["DBSnapshotAttributes"]:
                        if "all" in att["AttributeValues"]:
                            snapshot.public = True

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_db_cluster_snapshots__(self, regional_client):
        logger.info("RDS - Describe Cluster Snapshots...")
        try:
            describe_db_snapshots_paginator = regional_client.get_paginator(
                "describe_db_cluster_snapshots"
            )
            for page in describe_db_snapshots_paginator.paginate():
                for snapshot in page["DBClusterSnapshots"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            snapshot["DBClusterSnapshotIdentifier"],
                            self.audit_resources,
                        )
                    ):
                        if snapshot["Engine"] != "docdb":
                            print(snapshot)
                            self.db_cluster_snapshots.append(
                                ClusterSnapshot(
                                    id=snapshot["DBClusterSnapshotIdentifier"],
                                    cluster_id=snapshot["DBClusterIdentifier"],
                                    region=regional_client.region,
                                    tags=snapshot.get("TagList"),
                                )
                            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_db_cluster_snapshot_attributes__(self, regional_client):
        logger.info("RDS - Describe Cluster Snapshot Attributes...")
        try:
            for snapshot in self.db_cluster_snapshots:
                if snapshot.region == regional_client.region:
                    response = regional_client.describe_db_cluster_snapshot_attributes(
                        DBClusterSnapshotIdentifier=snapshot.id
                    )["DBClusterSnapshotAttributesResult"]
                    for att in response["DBClusterSnapshotAttributes"]:
                        if "all" in att["AttributeValues"]:
                            snapshot.public = True

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class DBInstance(BaseModel):
    id: str
    endpoint: Optional[dict]
    engine: str
    status: str
    public: bool
    encrypted: bool
    backup_retention_period: int = 0
    cloudwatch_logs: Optional[list]
    deletion_protection: bool
    auto_minor_version_upgrade: bool
    enhanced_monitoring_arn: Optional[str]
    multi_az: bool
    region: str
    tags: Optional[list] = []


class DBSnapshot(BaseModel):
    id: str
    instance_id: str
    public: bool = False
    region: str
    tags: Optional[list] = []


class ClusterSnapshot(BaseModel):
    id: str
    cluster_id: str
    public: bool = False
    region: str
    tags: Optional[list] = []
