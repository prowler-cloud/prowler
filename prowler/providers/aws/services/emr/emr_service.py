import threading
from enum import Enum

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## EMR
class EMR:
    def __init__(self, audit_info):
        self.service = "emr"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.clusters = {}
        self.block_public_access_configuration = {}
        self.__threading_call__(self.__list_clusters__)
        self.__threading_call__(self.__describe_cluster__)
        self.__threading_call__(self.__get_block_public_access_configuration__)

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
        logger.info("EMR - Listing Clusters...")
        try:
            list_clusters_paginator = regional_client.get_paginator("list_clusters")
            for page in list_clusters_paginator.paginate():
                for cluster in page["Clusters"]:
                    cluster_name = cluster["Name"]
                    cluster_id = cluster["Id"]
                    cluster_arn = cluster["ClusterArn"]
                    cluster_status = cluster["Status"]["State"]

                    self.clusters[cluster_id] = Cluster(
                        id=cluster_id,
                        name=cluster_name,
                        arn=cluster_arn,
                        status=cluster_status,
                        region=regional_client.region,
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __describe_cluster__(self, regional_client):
        logger.info("EMR - Describing Clusters...")
        try:
            for cluster in self.clusters.values():
                if cluster.region == regional_client.region:
                    describe_cluster_parameters = {"ClusterId": cluster.id}
                    cluster_info = regional_client.describe_cluster(
                        **describe_cluster_parameters
                    )

                    # Master Node Security Groups
                    master_node_security_group = cluster_info["Cluster"][
                        "Ec2InstanceAttributes"
                    ]["EmrManagedMasterSecurityGroup"]
                    master_node_additional_security_groups = cluster_info["Cluster"][
                        "Ec2InstanceAttributes"
                    ]["AdditionalMasterSecurityGroups"]
                    self.clusters[cluster.id].master = Node(
                        security_group_id=master_node_security_group,
                        additional_security_groups_id=master_node_additional_security_groups,
                    )

                    # Slave Node Security Groups
                    slave_node_security_group = cluster_info["Cluster"][
                        "Ec2InstanceAttributes"
                    ]["EmrManagedSlaveSecurityGroup"]
                    slave_node_additional_security_groups = cluster_info["Cluster"][
                        "Ec2InstanceAttributes"
                    ]["AdditionalSlaveSecurityGroups"]
                    self.clusters[cluster.id].slave = Node(
                        security_group_id=slave_node_security_group,
                        additional_security_groups_id=slave_node_additional_security_groups,
                    )

                    # Save MasterPublicDnsName
                    master_public_dns_name = cluster_info["Cluster"][
                        "MasterPublicDnsName"
                    ]
                    self.clusters[
                        cluster.id
                    ].master_public_dns_name = master_public_dns_name
                    # Set cluster Public/Private
                    # Public EMR cluster have their DNS ending with .amazonaws.com
                    # while private ones have format of ip-xxx-xx-xx.us-east-1.compute.internal.
                    if ".amazonaws.com" in master_public_dns_name:
                        self.clusters[cluster.id].public = True

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __get_block_public_access_configuration__(self, regional_client):
        """Returns the Amazon EMR block public access configuration for your Amazon Web Services account in the current Region."""
        logger.info("EMR - Getting Block Public Access Configuration...")
        try:
            block_public_access_configuration = (
                regional_client.get_block_public_access_configuration()
            )

            self.block_public_access_configuration[
                regional_client.region
            ] = BlockPublicAccessConfiguration(
                block_public_security_group_rules=block_public_access_configuration[
                    "BlockPublicAccessConfiguration"
                ]["BlockPublicSecurityGroupRules"]
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )


class BlockPublicAccessConfiguration(BaseModel):
    block_public_security_group_rules: bool


class ClusterStatus(Enum):
    STARTING = "STARTING"
    BOOTSTRAPPING = "BOOTSTRAPPING"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    TERMINATED_WITH_ERRORS = "TERMINATED_WITH_ERRORS"


class Node(BaseModel):
    security_group_id: str = ""
    additional_security_groups_id: list[str] = []


class Cluster(BaseModel):
    id: str
    name: str
    status: ClusterStatus
    arn: str
    region: str
    master: Node = Node()
    slave: Node = Node()
    master_public_dns_name: str = ""
    public: bool = False
