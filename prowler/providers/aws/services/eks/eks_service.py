from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ EKS
class EKS(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.clusters = []
        self.__threading_call__(self.__list_clusters__)
        self.__describe_cluster__(self.regional_clients)

    def __list_clusters__(self, regional_client):
        logger.info("EKS listing clusters...")
        try:
            list_clusters_paginator = regional_client.get_paginator("list_clusters")
            for page in list_clusters_paginator.paginate():
                for cluster in page["clusters"]:
                    arn = f"arn:{self.audited_partition}:eks:{regional_client.region}:{self.audited_account}:cluster/{cluster}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.clusters.append(
                            EKSCluster(
                                arn=arn,
                                name=cluster,
                                region=regional_client.region,
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_cluster__(self, regional_clients):
        logger.info("EKS listing clusters...")
        try:
            for cluster in self.clusters:
                regional_client = regional_clients[cluster.region]
                describe_cluster = regional_client.describe_cluster(name=cluster.name)
                if "logging" in describe_cluster["cluster"]:
                    cluster.logging = EKSClusterLoggingEntity(
                        types=describe_cluster["cluster"]["logging"]["clusterLogging"][
                            0
                        ]["types"],
                        enabled=describe_cluster["cluster"]["logging"][
                            "clusterLogging"
                        ][0]["enabled"],
                    )
                if (
                    "clusterSecurityGroupId"
                    in describe_cluster["cluster"]["resourcesVpcConfig"]
                ):
                    cluster.security_group_id = describe_cluster["cluster"][
                        "resourcesVpcConfig"
                    ]["clusterSecurityGroupId"]
                if (
                    "endpointPublicAccess"
                    in describe_cluster["cluster"]["resourcesVpcConfig"]
                ):
                    cluster.endpoint_public_access = describe_cluster["cluster"][
                        "resourcesVpcConfig"
                    ]["endpointPublicAccess"]
                if (
                    "endpointPrivateAccess"
                    in describe_cluster["cluster"]["resourcesVpcConfig"]
                ):
                    cluster.endpoint_private_access = describe_cluster["cluster"][
                        "resourcesVpcConfig"
                    ]["endpointPrivateAccess"]
                if (
                    "publicAccessCidrs"
                    in describe_cluster["cluster"]["resourcesVpcConfig"]
                ):
                    cluster.public_access_cidrs = describe_cluster["cluster"][
                        "resourcesVpcConfig"
                    ]["publicAccessCidrs"]
                if "encryptionConfig" in describe_cluster["cluster"]:
                    cluster.encryptionConfig = True
                cluster.tags = [describe_cluster["cluster"].get("tags")]

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class EKSClusterLoggingEntity(BaseModel):
    types: list[str] = None
    enabled: bool = None


class EKSCluster(BaseModel):
    name: str
    arn: str
    region: str
    logging: EKSClusterLoggingEntity = None
    security_group_id: str = None
    endpoint_public_access: bool = None
    endpoint_private_access: bool = None
    public_access_cidrs: list[str] = None
    encryptionConfig: bool = None
    tags: Optional[list] = []
