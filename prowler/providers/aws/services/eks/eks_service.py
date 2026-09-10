from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService

# DescribeAddon has no batch form, so only add-ons a check reads are described.
COLLECTED_ADDONS = ("vpc-cni",)


class EKS(AWSService):
    def __init__(self, provider):
        """Collect the audited account's EKS clusters, their configuration and their add-ons."""
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.clusters = []
        self.__threading_call__(self._list_clusters)
        self._describe_cluster(self.regional_clients)
        self.__threading_call__(self._describe_cluster_addons, self.clusters)

    def _list_clusters(self, regional_client):
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

    def _describe_cluster(self, regional_clients):
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
                if "deletionProtection" in describe_cluster["cluster"]:
                    cluster.deletion_protection = describe_cluster["cluster"][
                        "deletionProtection"
                    ]
                cluster.tags = [describe_cluster["cluster"].get("tags")]
                cluster.version = describe_cluster["cluster"].get("version", "")

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_cluster_addons(self, cluster):
        """Attach the add-ons named in COLLECTED_ADDONS, with their configuration, to a cluster.

        ListAddons names every add-on installed on the cluster and DescribeAddon then supplies
        the ARN and the raw `configurationValues` blob for the ones checks read. A failed listing
        sets `addons_discovery_failed` on the cluster and a failed describe sets
        `configuration_discovery_failed` on the add-on, so a check can tell an add-on that is
        absent from one whose state could not be read instead of reporting both as absent.
        """
        logger.info("EKS describing cluster add-ons...")
        try:
            regional_client = self.regional_clients[cluster.region]
            list_addons_paginator = regional_client.get_paginator("list_addons")
            for page in list_addons_paginator.paginate(clusterName=cluster.name):
                for addon_name in page["addons"]:
                    if addon_name in COLLECTED_ADDONS:
                        cluster.addons[addon_name] = EKSAddon(name=addon_name)
        except Exception as error:
            cluster.addons_discovery_failed = True
            logger.error(
                f"{cluster.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return

        for addon in cluster.addons.values():
            try:
                describe_addon = regional_client.describe_addon(
                    clusterName=cluster.name, addonName=addon.name
                )
                addon.arn = describe_addon["addon"].get("addonArn")
                addon.configuration_values = describe_addon["addon"].get(
                    "configurationValues"
                )
            except Exception as error:
                addon.configuration_discovery_failed = True
                logger.error(
                    f"{cluster.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class EKSClusterLoggingEntity(BaseModel):
    types: list[str] = None
    enabled: bool = None


class EKSAddon(BaseModel):
    """An EKS managed add-on, with the configuration values collected for it.

    Attributes:
        name: The add-on name as returned by ListAddons.
        arn: The add-on ARN, absent when DescribeAddon could not be read.
        configuration_values: The raw JSON blob supplied for the add-on, absent when none
            was supplied or when DescribeAddon could not be read.
        configuration_discovery_failed: True when DescribeAddon failed, so a check can
            tell a setting that is unset from one that could not be read.
    """

    name: str
    arn: Optional[str] = None
    configuration_values: Optional[str] = None
    configuration_discovery_failed: bool = False


class EKSCluster(BaseModel):
    name: str
    arn: str
    region: str
    version: str = None
    logging: EKSClusterLoggingEntity = None
    security_group_id: str = None
    endpoint_public_access: bool = None
    endpoint_private_access: bool = None
    public_access_cidrs: list[str] = []
    encryptionConfig: bool = None
    deletion_protection: bool = None
    addons: dict[str, EKSAddon] = {}
    addons_discovery_failed: bool = False
    tags: Optional[list] = []
