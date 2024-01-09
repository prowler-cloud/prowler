from typing import Optional

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
        self.__threading_call__(self.__describe_clusters__)
        self.__threading_call__(self.__describe_db_subnet_groups__)
        self.__list_tags_for_resource__()

    def __describe_clusters__(self, regional_client):
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
                        db_subnet_group_id=cluster["DBSubnetGroup"],
                        region=regional_client.region,
                    )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_db_subnet_groups__(self, regional_client):
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

    def __list_tags_for_resource__(self):
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


class Cluster(BaseModel):
    arn: str
    name: str
    id: str
    region: str
    db_subnet_group_id: str
    subnets: Optional[list]
    tags: Optional[list]
