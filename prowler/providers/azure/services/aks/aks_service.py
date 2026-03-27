from dataclasses import dataclass
from typing import List

from azure.mgmt.containerservice import ContainerServiceClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class AKS(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(ContainerServiceClient, provider)
        self.clusters = self._get_clusters()

    def _get_clusters(self):
        logger.info("AKS - Getting clusters...")
        clusters = {}

        for subscription_name, client in self.clients.items():
            try:
                clusters.update({subscription_name: {}})
                clusters_list = []
                if self.resource_groups is not None:
                    rgs = self.resource_groups.get(subscription_name, [])

                    if not rgs:
                        logger.warning(
                            f"No valid resource groups for subscription {subscription_name}"
                        )
                    else:
                        for rg in rgs:
                            try:
                                clusters_list += list(
                                    client.managed_clusters.list_by_resource_group(
                                        resource_group_name=rg
                                    )
                                )
                            except Exception as error:
                                logger.warning(
                                    f"Subscription name: {subscription_name} -- Resource Group: {rg} -- "
                                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                else:
                    clusters_list = client.managed_clusters.list()

                for cluster in clusters_list:
                    if getattr(cluster, "kubernetes_version", None):
                        clusters[subscription_name].update(
                            {
                                cluster.id: Cluster(
                                    id=cluster.id,
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
                                    agent_pool_profiles=[
                                        ManagedClusterAgentPoolProfile(
                                            name=agent_pool_profile.name,
                                            enable_node_public_ip=getattr(
                                                agent_pool_profile,
                                                "enable_node_public_ip",
                                                False,
                                            ),
                                        )
                                        for agent_pool_profile in getattr(
                                            cluster, "agent_pool_profiles", []
                                        )
                                    ],
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
class ManagedClusterAgentPoolProfile:
    name: str
    enable_node_public_ip: bool


@dataclass
class Cluster:
    id: str
    name: str
    public_fqdn: str
    private_fqdn: str
    network_policy: str
    agent_pool_profiles: List[ManagedClusterAgentPoolProfile]
    rbac_enabled: bool
    location: str
