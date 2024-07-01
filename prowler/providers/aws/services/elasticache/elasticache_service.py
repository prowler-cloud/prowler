from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ Elasticache
class ElastiCache(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.clusters = {}
        self.replication_groups = {}
        self.__threading_call__(self.__describe_cache_clusters__)
        self.__threading_call__(self.__describe_cache_subnet_groups__)
        self.__threading_call__(self.__describe_replication_groups__)
        self.__list_tags_for_resource__()

    def __describe_cache_clusters__(self, regional_client):
        # Memcached Clusters and Redis Nodes
        logger.info("Elasticache - Describing Cache Clusters...")
        try:
            for cache_cluster in regional_client.describe_cache_clusters()[
                "CacheClusters"
            ]:
                try:
                    cluster_arn = cache_cluster["ARN"]
                    if not self.audit_resources or (
                        is_resource_filtered(cluster_arn, self.audit_resources)
                    ):
                        self.clusters[cluster_arn] = Cluster(
                            id=cache_cluster["CacheClusterId"],
                            arn=cluster_arn,
                            region=regional_client.region,
                            engine=cache_cluster["Engine"],
                            cache_subnet_group_id=cache_cluster.get(
                                "CacheSubnetGroupName", None
                            ),
                        )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_cache_subnet_groups__(self, regional_client):
        logger.info("Elasticache - Describing Cache Subnet Groups...")
        try:
            for cluster in self.clusters.values():
                if cluster.region == regional_client.region:
                    try:
                        subnets = []
                        if cluster.cache_subnet_group_id:
                            cache_subnet_groups = (
                                regional_client.describe_cache_subnet_groups(
                                    CacheSubnetGroupName=cluster.cache_subnet_group_id
                                )["CacheSubnetGroups"]
                            )
                            for subnet_group in cache_subnet_groups:
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

    def __describe_replication_groups__(self, regional_client):
        # Redis Clusters
        logger.info("Elasticache - Describing Replication Groups...")
        try:
            for repl_group in regional_client.describe_replication_groups()[
                "ReplicationGroups"
            ]:
                try:
                    replication_arn = repl_group["ARN"]
                    if not self.audit_resources or (
                        is_resource_filtered(replication_arn, self.audit_resources)
                    ):
                        self.replication_groups[replication_arn] = ReplicationGroup(
                            id=repl_group["ReplicationGroupId"],
                            arn=replication_arn,
                            region=regional_client.region,
                            status=repl_group["Status"],
                            snapshot_retention=repl_group.get(
                                "SnapshotRetentionLimit", 0
                            ),
                            encrypted=repl_group.get("AtRestEncryptionEnabled", False),
                            transit_encryption=repl_group.get(
                                "TransitEncryptionEnabled", False
                            ),
                            multi_az=repl_group.get("MultiAZ", "disabled"),
                        )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_tags_for_resource__(self):
        logger.info("Elasticache - Listing Tags...")
        try:
            for cluster in self.clusters.values():
                try:
                    regional_client = self.regional_clients[cluster.region]
                    cluster.tags = regional_client.list_tags_for_resource(
                        ResourceName=cluster.arn
                    )["TagList"]
                except regional_client.exceptions.CacheClusterNotFoundFault as error:
                    logger.warning(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            for repl_group in self.replication_groups.values():
                try:
                    regional_client = self.regional_clients[repl_group.region]
                    repl_group.tags = regional_client.list_tags_for_resource(
                        ResourceName=repl_group.arn
                    )["TagList"]
                except (
                    regional_client.exceptions.ReplicationGroupNotFoundFault
                ) as error:
                    logger.warning(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Cluster(BaseModel):
    id: str
    arn: str
    region: str
    engine: str
    cache_subnet_group_id: Optional[str]
    subnets: list = []
    tags: Optional[list]


class ReplicationGroup(BaseModel):
    id: str
    arn: str
    region: str
    status: str
    snapshot_retention: int
    encrypted: bool
    transit_encryption: bool
    multi_az: str
    tags: Optional[list]
