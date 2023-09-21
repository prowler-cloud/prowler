from pydantic import BaseModel, typing

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService



################## NetworkFirewall
class Neptune(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.clusters = []
        self.__describe_clusters__()

    def __describe_clusters__(self):
        logger.info("Neptune - Describing DB Clusters...")
        try:
            for cluster in self.client.describe_db_clusters()["DBClusters"]:
                self.clusters.append(Cluster(
                    arn=cluster["DBClusterArn"],
                    name=cluster["DBClusterIdentifier"],
                    id=cluster["DbClusterResourceId"],
                    subnet_group=self.client.describe_db_subnet_groups(DBSubnetGroupName=cluster["DBSubnetGroup"])["DBSubnetGroups"]
                ))
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Cluster(BaseModel):
    arn: str
    name: str
    id: str
    subnet_group: typing.Any
