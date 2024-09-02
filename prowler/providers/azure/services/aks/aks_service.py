from dataclasses import dataclass

from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.containerservice.models import ManagedClusterAgentPoolProfile

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


########################## AKS (Azure Kubernetes Service)
class AKS(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(ContainerServiceClient, provider)
        self.clusters = self._get_clusters()

    def _get_clusters(self):
        logger.info("AKS - Getting clusters...")
        clusters = {}

        for subscription_name, client in self.clients.items():
            try:
                clusters_list = client.managed_clusters.list()
                clusters.update({subscription_name: {}})

                for cluster in clusters_list:
                    if getattr(cluster, "kubernetes_version", None):
                        clusters[subscription_name].update(
                            {
                                cluster.id: Cluster(
                                    name=cluster.name,
                                    public_fqdn=cluster.fqdn,
                                    private_fqdn=cluster.private_fqdn,
                                    location=cluster.location,
                                    network_policy=(
                                        getattr(
                                            cluster.network_profile,
                                            "network_policy",
                                            None,
                                        )
                                        if getattr(cluster, "network_profile", None)
                                        else None
                                    ),
                                    agent_pool_profiles=getattr(
                                        cluster, "agent_pool_profiles", []
                                    ),
                                    rbac_enabled=getattr(cluster, "enable_rbac", False),
                                )
                            }
                        )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return clusters


@dataclass
class Cluster:
    name: str
    public_fqdn: str
    private_fqdn: str
    network_policy: str
    agent_pool_profiles: list[ManagedClusterAgentPoolProfile]
    rbac_enabled: bool
    location: str
