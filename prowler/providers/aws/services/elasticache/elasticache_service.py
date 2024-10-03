from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class ElastiCache(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.clusters = {}
        self.replication_groups = {}
        self.__threading_call__(self._describe_cache_clusters)
        self.__threading_call__(self._describe_cache_subnet_groups)
        self.__threading_call__(self._describe_replication_groups)
        self._list_tags_for_resource()

    def _describe_cache_clusters(self, regional_client):
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
                            auto_minor_version_upgrade=cache_cluster.get(
                                "AutoMinorVersionUpgrade", False
                            ),
                            engine_version=cache_cluster.get("EngineVersion", "0.0"),
                            auth_token_enabled=cache_cluster.get(
                                "AuthTokenEnabled", False
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

    def _describe_cache_subnet_groups(self, regional_client):
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

    def _describe_replication_groups(self, regional_client):
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
                        # Get first cluster version as they all have the same unless an upgrade is being made
                        member_clusters = repl_group.get("MemberClusters", [])
                        engine_version = "0.0"
                        if member_clusters:
                            cluster_arn = f"arn:{self.audited_partition}:elasticache:{regional_client.region}:{self.audited_account}:cluster:{member_clusters[0]}"
                            engine_version = self.clusters[cluster_arn].engine_version

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
                            auto_minor_version_upgrade=repl_group.get(
                                "AutoMinorVersionUpgrade", False
                            ),
                            automatic_failover=repl_group.get(
                                "AutomaticFailover", "disabled"
                            ),
                            auth_token_enabled=repl_group.get(
                                "AuthTokenEnabled", False
                            ),
                            engine_version=engine_version,
                        )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
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
    auto_minor_version_upgrade: bool = False
    engine_version: Optional[str]
    auth_token_enabled: Optional[bool]


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
    auth_token_enabled: bool
    auto_minor_version_upgrade: bool
    automatic_failover: str
    engine_version: str
