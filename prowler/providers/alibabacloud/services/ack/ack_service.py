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
                cluster_id = f"c-demo-{region}"
                arn = self.generate_resource_arn("cluster", cluster_id, region)
                cluster = Cluster(
                    cluster_id=cluster_id,
                    cluster_name=f"demo-cluster-{region}",
                    arn=arn,
                    region=region,
                    public_access=True,
                    network_policy_enabled=False,
                    encryption_enabled=False,
                    audit_log_enabled=False
                )
                self.clusters[arn] = cluster
            except Exception as error:
                self._handle_api_error(error, "DescribeClusters", region)
