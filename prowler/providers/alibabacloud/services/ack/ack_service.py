"""Alibaba Cloud ACK Service"""

from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


@dataclass
class Cluster:
    """ACK Cluster"""

    cluster_id: str
    cluster_name: str
    arn: str
    region: str
    cluster_type: str = "Kubernetes"
    state: str = "running"
    public_access: bool = True  # Will trigger check
    private_zone_enabled: bool = False
    network_policy_enabled: bool = False  # Will trigger check
    rbac_enabled: bool = True
    encryption_enabled: bool = False  # Will trigger check
    audit_log_enabled: bool = False  # Will trigger check
    security_group_id: str = ""
    vpc_id: str = ""
    master_url: str = ""

    def __post_init__(self):
        pass


class ACK(AlibabaCloudService):
    def __init__(self, provider):
        super().__init__("ack", provider)
        self.clusters = {}
        logger.info("Collecting ACK clusters...")
        self._describe_clusters()
        logger.info(f"ACK service initialized - Clusters: {len(self.clusters)}")

    def _describe_clusters(self):
        for region in self.regions:
            try:
                from alibabacloud_cs20151215.client import Client as AckClient
                from alibabacloud_tea_openapi import models as openapi_models

                # Create client configuration
                config = openapi_models.Config(
                    access_key_id=self.provider.session.credentials.access_key_id,
                    access_key_secret=self.provider.session.credentials.access_key_secret,
                    region_id=region,
                )

                if self.provider.session.credentials.security_token:
                    config.security_token = (
                        self.provider.session.credentials.security_token
                    )

                # Create ACK client
                client = AckClient(config)

                # List clusters
                response = client.describe_clusters_v1()

                # Process clusters
                if response.body and response.body.clusters:
                    for cluster_data in response.body.clusters:
                        cluster_id = cluster_data.cluster_id
                        arn = self.generate_resource_arn("cluster", cluster_id, region)

                        # Get detailed cluster info
                        try:
                            detail_response = client.describe_cluster_detail(cluster_id)
                            detail = (
                                detail_response.body
                                if detail_response.body
                                else cluster_data
                            )

                            # Check audit log
                            audit_log_enabled = False
                            if hasattr(detail, "parameters") and detail.parameters:
                                audit_log_enabled = (
                                    detail.parameters.get("AuditLogEnabled", "false")
                                    == "true"
                                )

                            # Check encryption
                            encryption_enabled = False
                            if hasattr(detail, "parameters") and detail.parameters:
                                encryption_enabled = (
                                    detail.parameters.get("EncryptionEnabled", "false")
                                    == "true"
                                )

                            # Check network policy
                            network_policy_enabled = False
                            if hasattr(detail, "parameters") and detail.parameters:
                                network_policy_enabled = (
                                    detail.parameters.get("NetworkPlugin", "")
                                    == "terway"
                                )

                            # Check RBAC
                            rbac_enabled = (
                                True  # Default to true for modern ACK clusters
                            )
                            if hasattr(detail, "parameters") and detail.parameters:
                                rbac_enabled = (
                                    detail.parameters.get("RBACEnabled", "true")
                                    == "true"
                                )

                            # Check private zone
                            private_zone_enabled = False
                            if hasattr(detail, "private_zone", "false"):
                                private_zone_enabled = detail.private_zone

                            cluster = Cluster(
                                cluster_id=cluster_id,
                                cluster_name=(
                                    cluster_data.name
                                    if cluster_data.name
                                    else cluster_id
                                ),
                                arn=arn,
                                region=region,
                                cluster_type=(
                                    cluster_data.cluster_type
                                    if hasattr(cluster_data, "cluster_type")
                                    else "Kubernetes"
                                ),
                                state=(
                                    cluster_data.state
                                    if hasattr(cluster_data, "state")
                                    else "running"
                                ),
                                public_access=(
                                    hasattr(cluster_data, "public_slb")
                                    and cluster_data.public_slb
                                    if hasattr(cluster_data, "public_slb")
                                    else False
                                ),
                                private_zone_enabled=private_zone_enabled,
                                network_policy_enabled=network_policy_enabled,
                                rbac_enabled=rbac_enabled,
                                encryption_enabled=encryption_enabled,
                                audit_log_enabled=audit_log_enabled,
                                security_group_id=(
                                    cluster_data.security_group_id
                                    if hasattr(cluster_data, "security_group_id")
                                    else ""
                                ),
                                vpc_id=(
                                    cluster_data.vpc_id
                                    if hasattr(cluster_data, "vpc_id")
                                    else ""
                                ),
                                master_url=(
                                    cluster_data.master_url
                                    if hasattr(cluster_data, "master_url")
                                    else ""
                                ),
                            )

                            self.clusters[arn] = cluster
                            logger.info(f"Found ACK cluster: {cluster_id} in {region}")

                        except Exception as detail_error:
                            logger.warning(
                                f"Could not get details for cluster {cluster_id}: {detail_error}"
                            )
                            # Use basic cluster data
                            cluster = Cluster(
                                cluster_id=cluster_id,
                                cluster_name=(
                                    cluster_data.name
                                    if cluster_data.name
                                    else cluster_id
                                ),
                                arn=arn,
                                region=region,
                                vpc_id=(
                                    cluster_data.vpc_id
                                    if hasattr(cluster_data, "vpc_id")
                                    else ""
                                ),
                            )
                            self.clusters[arn] = cluster
                else:
                    logger.info(f"No ACK clusters found in {region}")

            except Exception as error:
                self._handle_api_error(error, "DescribeClusters", region)
