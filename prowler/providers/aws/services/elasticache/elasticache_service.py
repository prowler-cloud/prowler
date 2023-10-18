from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################################ Elasticache
class ElastiCache(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.clusters = {}
        self.__threading_call__(self.__describe_cache_clusters__)
        self.__threading_call__(self.__describe_cache_subnet_groups__)
        self.__list_tags_for_resource__()

    def __describe_cache_clusters__(self, regional_client):
        logger.info("Elasticache - Describing Cache Clusters...")
        try:
            for cache_cluster in regional_client.describe_cache_clusters()[
                "CacheClusters"
            ]:
                cluster_arn = cache_cluster["ARN"]
                self.clusters[cluster_arn] = Cluster(
                    id=cache_cluster["CacheClusterId"],
                    arn=cluster_arn,
                    region=regional_client.region,
                    cache_subnet_group_id=cache_cluster["CacheSubnetGroupName"],
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

    def __list_tags_for_resource__(self):
        logger.info("Elasticache - Listing Tags...")
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


class Cluster(BaseModel):
    id: str
    arn: str
    region: str
    cache_subnet_group_id: str
    subnets: Optional[list]
    tags: Optional[list]
