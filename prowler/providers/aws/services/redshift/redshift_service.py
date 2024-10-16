from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ Redshift
class Redshift(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.clusters = []
        self.__threading_call__(self._describe_clusters)
<<<<<<< HEAD
        self._describe_logging_status(self.regional_clients)
        self._describe_cluster_snapshots(self.regional_clients)
=======
        self.__threading_call__(self._describe_logging_status, self.clusters)
        self.__threading_call__(self._describe_cluster_snapshots, self.clusters)
        self.__threading_call__(self._describe_cluster_parameters, self.clusters)
        self.__threading_call__(self._describe_cluster_subnets, self.clusters)
>>>>>>> 6e3c008a8 (chore(aws): improve logic for determining if resources are publicly accessible (#5195))

    def _describe_clusters(self, regional_client):
        logger.info("Redshift - Describing Clusters...")
        try:
            list_clusters_paginator = regional_client.get_paginator("describe_clusters")
            for page in list_clusters_paginator.paginate():
                for cluster in page["Clusters"]:
                    arn = f"arn:{self.audited_partition}:redshift:{regional_client.region}:{self.audited_account}:cluster:{cluster['ClusterIdentifier']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        cluster_to_append = Cluster(
                            arn=arn,
                            id=cluster["ClusterIdentifier"],
<<<<<<< HEAD
                            region=regional_client.region,
                            tags=cluster.get("Tags"),
=======
                            vpc_id=cluster.get("VpcId"),
                            vpc_security_groups=[
                                sg["VpcSecurityGroupId"]
                                for sg in cluster.get("VpcSecurityGroups")
                                if sg["Status"] == "active"
                            ],
                            endpoint_address=cluster.get("Endpoint", {}).get(
                                "Address", ""
                            ),
                            public_access=cluster.get("PubliclyAccessible", False),
                            allow_version_upgrade=cluster.get(
                                "AllowVersionUpgrade", False
                            ),
                            encrypted=cluster.get("Encrypted", False),
                            region=regional_client.region,
                            tags=cluster.get("Tags"),
                            master_username=cluster.get("MasterUsername", ""),
                            enhanced_vpc_routing=cluster.get(
                                "EnhancedVpcRouting", False
                            ),
                            database_name=cluster.get("DBName", ""),
                            parameter_group_name=cluster.get(
                                "ClusterParameterGroups", [{}]
                            )[0].get("ParameterGroupName", ""),
                            subnet_group=cluster.get("ClusterSubnetGroupName", ""),
>>>>>>> 6e3c008a8 (chore(aws): improve logic for determining if resources are publicly accessible (#5195))
                        )
                        if (
                            "PubliclyAccessible" in cluster
                            and cluster["PubliclyAccessible"]
                        ):
                            cluster_to_append.public_access = True
                        if "Endpoint" in cluster and "Address" in cluster["Endpoint"]:
                            cluster_to_append.endpoint_address = cluster["Endpoint"][
                                "Address"
                            ]
                        if (
                            "AllowVersionUpgrade" in cluster
                            and cluster["AllowVersionUpgrade"]
                        ):
                            cluster_to_append.allow_version_upgrade = True
                        self.clusters.append(cluster_to_append)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

<<<<<<< HEAD
    def _describe_logging_status(self, regional_clients):
        logger.info("Redshift - describing logging status...")
=======
    def _describe_cluster_subnets(self, cluster):
        logger.info("Redshift - Describing Cluster Subnets...")
        try:
            regional_client = self.regional_clients[cluster.region]
            if cluster.subnet_group:
                subnet_group_details = regional_client.describe_cluster_subnet_groups(
                    ClusterSubnetGroupName=cluster.subnet_group
                )
                subnets = [
                    subnet["SubnetIdentifier"]
                    for subnet in subnet_group_details["ClusterSubnetGroups"][0][
                        "Subnets"
                    ]
                ]
                cluster.subnets = subnets
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_logging_status(self, cluster):
        logger.info("Redshift - Describing Logging Status...")
>>>>>>> 6e3c008a8 (chore(aws): improve logic for determining if resources are publicly accessible (#5195))
        try:
            for cluster in self.clusters:
                regional_client = regional_clients[cluster.region]
                cluster_attributes = regional_client.describe_logging_status(
                    ClusterIdentifier=cluster.id
                )
                if (
                    "LoggingEnabled" in cluster_attributes
                    and cluster_attributes["LoggingEnabled"]
                ):
                    cluster.logging_enabled = True
                if "BucketName" in cluster_attributes:
                    cluster.bucket = cluster_attributes["BucketName"]

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

<<<<<<< HEAD
    def _describe_cluster_snapshots(self, regional_clients):
        logger.info("Redshift - describing logging status...")
        try:
            for cluster in self.clusters:
                regional_client = regional_clients[cluster.region]
                cluster_snapshots = regional_client.describe_cluster_snapshots(
                    ClusterIdentifier=cluster.id
                )
                if "Snapshots" in cluster_snapshots and cluster_snapshots["Snapshots"]:
                    cluster.cluster_snapshots = True
=======
    def _describe_cluster_snapshots(self, cluster):
        logger.info("Redshift - Describing Cluster Status...")
        try:
            regional_client = self.regional_clients[cluster.region]
            cluster_snapshots = regional_client.describe_cluster_snapshots(
                ClusterIdentifier=cluster.id
            )
            if "Snapshots" in cluster_snapshots and cluster_snapshots["Snapshots"]:
                cluster.cluster_snapshots = True

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_cluster_parameters(self, cluster):
        logger.info("Redshift - Describing Cluster Parameter Groups...")
        try:
            regional_client = self.regional_clients[cluster.region]
            cluster_parameter_groups = regional_client.describe_cluster_parameters(
                ClusterParameterGroupName=cluster.parameter_group_name
            )
            for parameter_group in cluster_parameter_groups["Parameters"]:
                if parameter_group["ParameterName"].lower() == "require_ssl":
                    if parameter_group["ParameterValue"].lower() == "true":
                        cluster.require_ssl = True
>>>>>>> 6e3c008a8 (chore(aws): improve logic for determining if resources are publicly accessible (#5195))

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Cluster(BaseModel):
    id: str
    arn: str
    region: str
<<<<<<< HEAD
    public_access: bool = None
=======
    vpc_id: str = None
    vpc_security_groups: list = []
    public_access: bool = False
    encrypted: bool = False
    master_username: str = None
    database_name: str = None
>>>>>>> 6e3c008a8 (chore(aws): improve logic for determining if resources are publicly accessible (#5195))
    endpoint_address: str = None
    allow_version_upgrade: bool = None
    logging_enabled: bool = None
    bucket: str = None
    cluster_snapshots: bool = None
    tags: Optional[list] = []
<<<<<<< HEAD
=======
    enhanced_vpc_routing: bool = False
    parameter_group_name: str = None
    require_ssl: bool = False
    subnet_group: str = None
    subnets: list[str] = []
>>>>>>> 6e3c008a8 (chore(aws): improve logic for determining if resources are publicly accessible (#5195))
