import threading

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ EKS
class EKS:
    def __init__(self, audit_info):
        self.service = "eks"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.clusters = []
        self.__threading_call__(self.__list_clusters__)
        self.__describe_cluster__(self.regional_clients)

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

    def __list_clusters__(self, regional_client):
        logger.info("EKS listing clusters...")
        try:
            list_clusters_paginator = regional_client.get_paginator("list_clusters")
            for page in list_clusters_paginator.paginate():
                for cluster in page["clusters"]:
                    self.clusters.append(
                        EKSCluster(
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
                cluster.arn = describe_cluster["cluster"]["arn"]
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

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class EKSClusterLoggingEntity(BaseModel):
    types: list[str] = None
    enabled: bool = None


class EKSCluster(BaseModel):
    name: str
    arn: str = None
    region: str
    logging: EKSClusterLoggingEntity = None
    endpoint_public_access: bool = None
    endpoint_private_access: bool = None
    public_access_cidrs: list[str] = None
    encryptionConfig: bool = None
