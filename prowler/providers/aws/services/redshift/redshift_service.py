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
        self._describe_cluster_parameters(self.regional_clients)

    def _describe_clusters(self, regional_client):
        logger.info("Redshift - describing clusters...")
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
                            region=regional_client.region,
                            tags=cluster.get("Tags"),
                        )
                        if (
                            "PubliclyAccessible" in cluster
                            and cluster["PubliclyAccessible"]
                        ):
                            cluster_to_append.public_access = True
                        if "Endpoint" in cluster and "Address" in cluster["Endpoint"]:
                            cluster_to_append.endpoint_address = cluster["Endpoint"][
                                "Address"
                            ]
                        if (
                            "AllowVersionUpgrade" in cluster
                            and cluster["AllowVersionUpgrade"]
                        ):
                            cluster_to_append.allow_version_upgrade = True
                        if "ClusterParameterGroups" in cluster:
                            cluster_to_append.parameter_group_name = cluster[
                                "ClusterParameterGroups"
                            ][0]["ParameterGroupName"]
                        self.clusters.append(cluster_to_append)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_logging_status(self, regional_clients):
        logger.info("Redshift - describing logging status...")
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
        logger.info("Redshift - describing logging status...")
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

    def _describe_cluster_parameters(self, regional_clients):
        logger.info("Redshift - describing cluster parameter groups...")
        try:
            for cluster in self.clusters:
                regional_client = regional_clients[cluster.region]
                cluster_parameter_groups = regional_client.describe_cluster_parameters(
                    ClusterParameterGroupName=cluster.parameter_group_name
                )
                for parameter_group in cluster_parameter_groups["Parameters"]:
                    if parameter_group["ParameterName"].lower() == "require_ssl":
                        if parameter_group["ParameterValue"].lower() == "true":
                            cluster.require_ssl = True

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Cluster(BaseModel):
    id: str
    arn: str
    region: str
    public_access: bool = None
    endpoint_address: str = None
    allow_version_upgrade: bool = None
    logging_enabled: bool = None
    bucket: str = None
    cluster_snapshots: bool = None
    tags: Optional[list] = []
    parameter_group_name: str = None
    require_ssl: bool = False
