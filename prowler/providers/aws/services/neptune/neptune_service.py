from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## Neptune
class Neptune(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        self.service_name = "neptune"
        super().__init__(self.service_name, provider)
        self.clusters = {}
        self.db_cluster_snapshots = []
        self.__threading_call__(self._describe_clusters)
        self.__threading_call__(self._describe_db_subnet_groups)
        self.__threading_call__(self._describe_db_cluster_snapshots)
        self.__threading_call__(self._describe_db_cluster_snapshot_attributes)
        self._list_tags_for_resource()

    def _describe_clusters(self, regional_client):
        logger.info("Neptune - Describing DB Clusters...")
        try:
            for cluster in regional_client.describe_db_clusters(
                Filters=[
                    {
                        "Name": "engine",
                        "Values": [
                            self.service_name,
                        ],
                    },
                ],
            )["DBClusters"]:
                cluster_arn = cluster["DBClusterArn"]
                if not self.audit_resources or (
                    is_resource_filtered(cluster_arn, self.audit_resources)
                ):
                    self.clusters[cluster_arn] = Cluster(
                        arn=cluster_arn,
                        name=cluster["DBClusterIdentifier"],
                        id=cluster["DbClusterResourceId"],
                        backup_retention_period=cluster.get("BackupRetentionPeriod", 0),
                        encrypted=cluster.get("StorageEncrypted", False),
                        kms_key=cluster.get("KmsKeyId", ""),
                        cloudwatch_logs=cluster.get("EnabledCloudwatchLogsExports", []),
                        multi_az=cluster["MultiAZ"],
                        iam_auth=cluster.get("IAMDatabaseAuthenticationEnabled", False),
                        deletion_protection=cluster.get("DeletionProtection", False),
                        copy_tags_to_snapshot=cluster.get("CopyTagsToSnapshot", False),
                        db_subnet_group_id=cluster["DBSubnetGroup"],
                        region=regional_client.region,
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_db_subnet_groups(self, regional_client):
        logger.info("Neptune - Describing DB Subnet Groups...")
        try:
            for cluster in self.clusters.values():
                if cluster.region == regional_client.region:
                    try:
                        subnets = []
                        db_subnet_groups = regional_client.describe_db_subnet_groups(
                            DBSubnetGroupName=cluster.db_subnet_group_id
                        )["DBSubnetGroups"]
                        for subnet_group in db_subnet_groups:
                            for subnet in subnet_group["Subnets"]:
                                subnets.append(subnet["SubnetIdentifier"])

                        cluster.subnets = subnets
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
        logger.info("Neptune - Listing Tags...")
        try:
            for cluster in self.clusters.values():
                try:
                    regional_client = self.regional_clients[cluster.region]
                    cluster.tags = regional_client.list_tags_for_resource(
                        ResourceName=cluster.arn
                    )["TagList"]
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_db_cluster_snapshots(self, regional_client):
        logger.info("NeptuneDB - Describe Cluster Snapshots...")
        try:
            describe_db_snapshots_paginator = regional_client.get_paginator(
                "describe_db_cluster_snapshots"
            )
            for page in describe_db_snapshots_paginator.paginate():
                for snapshot in page["DBClusterSnapshots"]:
                    arn = f"arn:{self.audited_partition}:neptune:{regional_client.region}:{self.audited_account}:cluster-snapshot:{snapshot['DBClusterSnapshotIdentifier']}"
                    if not self.audit_resources or (
                        is_resource_filtered(
                            arn,
                            self.audit_resources,
                        )
                    ):
                        if snapshot["Engine"] == "neptune":
                            self.db_cluster_snapshots.append(
                                ClusterSnapshot(
                                    id=snapshot["DBClusterSnapshotIdentifier"],
                                    arn=arn,
                                    cluster_id=snapshot["DBClusterIdentifier"],
                                    encrypted=snapshot.get("StorageEncrypted", False),
                                    region=regional_client.region,
                                    tags=snapshot.get("TagList", []),
                                )
                            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_db_cluster_snapshot_attributes(self, regional_client):
        logger.info("NeptuneDB - Describe Cluster Snapshot Attributes...")
        try:
            for snapshot in self.db_cluster_snapshots:
                if snapshot.region == regional_client.region:
                    response = regional_client.describe_db_cluster_snapshot_attributes(
                        DBClusterSnapshotIdentifier=snapshot.id
                    )["DBClusterSnapshotAttributesResult"]
                    for att in response["DBClusterSnapshotAttributes"]:
                        if "all" in att["AttributeValues"]:
                            snapshot.public = True
        except ClientError as error:
            if error.response["Error"]["Code"] == "DBClusterSnapshotNotFoundFault":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Cluster(BaseModel):
    arn: str
    name: str
    id: str
    backup_retention_period: int
    encrypted: bool
    kms_key: str
    multi_az: bool
    iam_auth: bool
    deletion_protection: bool
    copy_tags_to_snapshot: Optional[bool]
    region: str
    db_subnet_group_id: str
    subnets: Optional[list]
    tags: Optional[list]
    cloudwatch_logs: Optional[list]


class ClusterSnapshot(BaseModel):
    id: str
    cluster_id: str
    arn: str
    public: bool = False
    encrypted: bool
    region: str
    tags: Optional[list] = []
