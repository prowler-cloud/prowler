from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


################## NetworkFirewall
class Neptune(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.clusters = []
        self.__describe_clusters__()
        self.__get_public_subnets__()

    def __describe_clusters__(self):
        logger.info("Neptune - Describing DB Clusters...")
        try:
            for cluster in self.client.describe_db_clusters(
                Filters=[
                    {
                        "Name": "engine",
                        "Values": [
                            "neptune",
                        ],
                    },
                ],
            )["DBClusters"]:
                self.clusters.append(
                    Cluster(
                        arn=cluster["DBClusterArn"],
                        name=cluster["DBClusterIdentifier"],
                        id=cluster["DbClusterResourceId"],
                        subnet_group=self.client.describe_db_subnet_groups(
                            DBSubnetGroupName=cluster["DBSubnetGroup"]
                        )["DBSubnetGroups"],
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_public_subnets__(self):
        for cluster in self.clusters:
            public_subnets = []
            for subnets in cluster.subnet_group:
                for subnet in subnets["Subnets"]:
                    if vpc_client.vpc_subnets[subnet["SubnetIdentifier"]].public:
                        public_subnets.append(
                            vpc_client.vpc_subnets[subnet["SubnetIdentifier"]].id
                        )
            cluster.public_subnets = public_subnets


class Cluster(BaseModel):
    arn: str
    name: str
    id: str
    subnet_group: list
    public_subnets: Optional[list] = []
