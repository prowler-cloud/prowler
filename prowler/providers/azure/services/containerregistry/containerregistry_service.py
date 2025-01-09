from dataclasses import dataclass

from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.containerregistry.models import (
    NetworkRuleSet,
    PrivateEndpointConnection,
)

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService
from prowler.providers.azure.services.monitor.monitor_client import monitor_client
from prowler.providers.azure.services.monitor.monitor_service import DiagnosticSetting


class ContainerRegistry(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(ContainerRegistryManagementClient, provider)
        self.registries = self._get_container_registries()

    def _get_container_registries(self):
        logger.info("Container Registry - Getting registries...")
        registries = {}
        for subscription, client in self.clients.items():
            try:
                registries_list = client.registries.list()
                registries.update({subscription: {}})

                for registry in registries_list:
                    resource_group = self._get_resource_group(registry.id)
                    registries[subscription].update(
                        {
                            registry.id: ContainerRegistryInfo(
                                id=getattr(registry, "id", ""),
                                name=getattr(registry, "name", ""),
                                location=getattr(registry, "location", ""),
                                resource_group=resource_group,
                                sku=getattr(registry.sku, "name", ""),
                                login_server=getattr(registry, "login_server", ""),
                                public_network_access=(
                                    False
                                    if getattr(
                                        registry, "public_network_access" "Enabled"
                                    )
                                    == "Disabled"
                                    else True
                                ),
                                admin_user_enabled=getattr(
                                    registry, "admin_user_enabled", False
                                ),
                                network_rule_set=getattr(
                                    registry, "network_rule_set", None
                                ),
                                monitor_diagnostic_settings=self._get_registry_monitor_settings(
                                    registry.name, resource_group, subscription
                                ),
                                private_endpoint_connections=getattr(
                                    registry, "private_endpoint_connections", []
                                ),
                            )
                        },
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return registries

    def _get_resource_group(self, registry_id: str) -> str:
        """Extract resource group from the registry ID."""
        return registry_id.split("/")[4]

    def _get_registry_monitor_settings(
        self, registry_name, resource_group, subscription
    ):
        logger.info(
            f"Container Registry - Getting monitor diagnostics settings for {registry_name}..."
        )
        monitor_diagnostics_settings = []
        try:
            monitor_diagnostics_settings = monitor_client.diagnostic_settings_with_uri(
                self.subscriptions[subscription],
                f"subscriptions/{self.subscriptions[subscription]}/resourceGroups/{resource_group}/providers/Microsoft.ContainerRegistry/registries/{registry_name}",
                monitor_client.clients[subscription],
            )
        except Exception as error:
            logger.error(
                f"Subscription name: {self.subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return monitor_diagnostics_settings


@dataclass
class ContainerRegistryInfo:
    id: str
    name: str
    location: str
    resource_group: str
    sku: str
    login_server: str
    public_network_access: bool
    admin_user_enabled: bool
    network_rule_set: NetworkRuleSet
    monitor_diagnostic_settings: list[DiagnosticSetting]
    private_endpoint_connections: list[PrivateEndpointConnection]
