from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Redshift(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.clusters = []
        self.__threading_call__(self._describe_clusters)
        self.__threading_call__(self._describe_logging_status, self.clusters)
        self.__threading_call__(self._describe_cluster_snapshots, self.clusters)
        self.__threading_call__(self._describe_cluster_parameters, self.clusters)
        self.__threading_call__(self._describe_cluster_subnets, self.clusters)

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
                            multi_az=cluster.get("MultiAZ", False),
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
                        )
                        self.clusters.append(cluster_to_append)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

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
        try:
            regional_client = self.regional_clients[cluster.region]
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

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Cluster(BaseModel):
    id: str
    arn: str
    region: str
    vpc_id: str = None
    vpc_security_groups: list = []
    public_access: bool = False
    encrypted: bool = False
    multi_az: bool = False
    master_username: str = None
    database_name: str = None
    endpoint_address: str = None
    allow_version_upgrade: bool = False
    logging_enabled: bool = False
    bucket: str = None
    cluster_snapshots: bool = False
    tags: Optional[list] = []
    enhanced_vpc_routing: bool = False
    parameter_group_name: str = None
    require_ssl: bool = False
    subnet_group: str = None
    subnets: list[str] = []
