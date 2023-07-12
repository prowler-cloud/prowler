import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ Redshift
class Redshift:
    def __init__(self, audit_info):
        self.service = "redshift"
        self.session = audit_info.audit_session
        self.audit_resources = audit_info.audit_resources
        self.audited_partition = audit_info.audited_partition
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.clusters = []
        self.__threading_call__(self.__describe_clusters__)
        self.__describe_logging_status__(self.regional_clients)
        self.__describe_cluster_snapshots__(self.regional_clients)

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

    def __describe_clusters__(self, regional_client):
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
                        self.clusters.append(cluster_to_append)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_logging_status__(self, regional_clients):
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

    def __describe_cluster_snapshots__(self, regional_clients):
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


class Cluster(BaseModel):
    id: str
    arn: str = ""
    region: str
    public_access: bool = None
    endpoint_address: str = None
    allow_version_upgrade: bool = None
    logging_enabled: bool = None
    bucket: str = None
    cluster_snapshots: bool = None
    tags: Optional[list] = []
