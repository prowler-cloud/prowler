from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Redshift(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.clusters = []
        self.__threading_call__(self._describe_clusters)
        self._describe_logging_status(self.regional_clients)
        self._describe_cluster_snapshots(self.regional_clients)

    def _describe_clusters(self, regional_client):
        logger.info("Redshift - Describing Clusters...")
        try:
            list_clusters_paginator = regional_client.get_paginator("describe_clusters")
            for page in list_clusters_paginator.paginate():
                for cluster in page["Clusters"]:
                    arn = f"arn:{self.audited_partition}:redshift:{regional_client.region}:{self.audited_account}:cluster:{cluster['ClusterIdentifier']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        cluster_to_append = Cluster(
                            arn=arn,
                            id=cluster["ClusterIdentifier"],
                            vpc_id=cluster.get("VpcId"),
                            vpc_security_groups=[
                                sg["VpcSecurityGroupId"]
                                for sg in cluster.get("VpcSecurityGroups")
                                if sg["Status"] == "active"
                            ],
                            endpoint_address=cluster.get("Endpoint", {}).get(
                                "Address", ""
                            ),
                            public_access=cluster.get("PubliclyAccessible", False),
                            allow_version_upgrade=cluster.get(
                                "AllowVersionUpgrade", False
                            ),
                            encrypted=cluster.get("Encrypted", False),
                            region=regional_client.region,
                            tags=cluster.get("Tags"),
                            master_username=cluster.get("MasterUsername", ""),
                        )
                        self.clusters.append(cluster_to_append)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_logging_status(self, regional_clients):
        logger.info("Redshift - Describing Logging Status...")
        try:
            for cluster in self.clusters:
                regional_client = regional_clients[cluster.region]
                cluster_attributes = regional_client.describe_logging_status(
                    ClusterIdentifier=cluster.id
                )
                if (
                    "LoggingEnabled" in cluster_attributes
                    and cluster_attributes["LoggingEnabled"]
                ):
                    cluster.logging_enabled = True
                if "BucketName" in cluster_attributes:
                    cluster.bucket = cluster_attributes["BucketName"]

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_cluster_snapshots(self, regional_clients):
        logger.info("Redshift - Describing Cluster Snapshots...")
        try:
            for cluster in self.clusters:
                regional_client = regional_clients[cluster.region]
                cluster_snapshots = regional_client.describe_cluster_snapshots(
                    ClusterIdentifier=cluster.id
                )
                if "Snapshots" in cluster_snapshots and cluster_snapshots["Snapshots"]:
                    cluster.cluster_snapshots = True

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Cluster(BaseModel):
    id: str
    arn: str
    region: str
    vpc_id: str = None
    vpc_security_groups: list = []
    public_access: bool = False
    encrypted: bool = False
    master_username: str = None
    endpoint_address: str = None
    allow_version_upgrade: bool = False
    logging_enabled: bool = False
    bucket: str = None
    cluster_snapshots: bool = False
    tags: Optional[list] = []
