from enum import Enum
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## EMR
class EMR(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.clusters = {}
        self.block_public_access_configuration = {}
        self.__threading_call__(self.__list_clusters__)
        self.__threading_call__(self.__describe_cluster__)
        self.__threading_call__(self.__get_block_public_access_configuration__)

    def __get_cluster_arn_template__(self, region):
        return f"arn:{self.audited_partition}:elasticmapreduce:{region}:{self.audited_account}:cluster"

    def __list_clusters__(self, regional_client):
        logger.info("EMR - Listing Clusters...")
        try:
            list_clusters_paginator = regional_client.get_paginator("list_clusters")
            for page in list_clusters_paginator.paginate():
                for cluster in page["Clusters"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            cluster["ClusterArn"], self.audit_resources
                        )
                    ):
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
                    try:
                        describe_cluster_parameters = {"ClusterId": cluster.id}
                        cluster_info = regional_client.describe_cluster(
                            **describe_cluster_parameters
                        )
                    except ClientError as error:
                        if error.response["Error"]["Code"] == "InvalidRequestException":
                            logger.warning(
                                f"{regional_client.region} --"
                                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                                f" {error}"
                            )
                        continue

                    # Master Node Security Groups
                    master_node_security_group = cluster_info["Cluster"][
                        "Ec2InstanceAttributes"
                    ].get("EmrManagedMasterSecurityGroup")
                    master_node_additional_security_groups = None
                    if (
                        "AdditionalMasterSecurityGroups"
                        in cluster_info["Cluster"]["Ec2InstanceAttributes"]
                    ):
                        master_node_additional_security_groups = cluster_info[
                            "Cluster"
                        ]["Ec2InstanceAttributes"]["AdditionalMasterSecurityGroups"]
                    self.clusters[cluster.id].master = Node(
                        security_group_id=master_node_security_group,
                        additional_security_groups_id=master_node_additional_security_groups,
                    )

                    # Slave Node Security Groups
                    slave_node_security_group = cluster_info["Cluster"][
                        "Ec2InstanceAttributes"
                    ].get("EmrManagedSlaveSecurityGroup")
                    slave_node_additional_security_groups = []
                    if (
                        "AdditionalSlaveSecurityGroups"
                        in cluster_info["Cluster"]["Ec2InstanceAttributes"]
                    ):
                        slave_node_additional_security_groups = cluster_info["Cluster"][
                            "Ec2InstanceAttributes"
                        ]["AdditionalSlaveSecurityGroups"]
                    self.clusters[cluster.id].slave = Node(
                        security_group_id=slave_node_security_group,
                        additional_security_groups_id=slave_node_additional_security_groups,
                    )

                    # Save MasterPublicDnsName
                    master_public_dns_name = cluster_info["Cluster"].get(
                        "MasterPublicDnsName"
                    )
                    self.clusters[cluster.id].master_public_dns_name = (
                        master_public_dns_name
                    )
                    # Set cluster Public/Private
                    # Public EMR cluster have their DNS ending with .amazonaws.com
                    # while private ones have format of ip-xxx-xx-xx.us-east-1.compute.internal.
                    if (
                        master_public_dns_name
                        and ".amazonaws.com" in master_public_dns_name
                    ):
                        self.clusters[cluster.id].public = True
                    cluster.tags = cluster_info["Cluster"].get("Tags")

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

            self.block_public_access_configuration[regional_client.region] = (
                BlockPublicAccessConfiguration(
                    block_public_security_group_rules=block_public_access_configuration[
                        "BlockPublicAccessConfiguration"
                    ]["BlockPublicSecurityGroupRules"]
                )
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
    security_group_id: Optional[str] = ""
    additional_security_groups_id: Optional[list[str]] = []


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
    tags: Optional[list] = []
