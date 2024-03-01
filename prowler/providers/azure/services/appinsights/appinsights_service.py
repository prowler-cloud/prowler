from dataclasses import dataclass

from azure.mgmt.applicationinsights import ApplicationInsightsManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


########################## AppInsights
class AppInsights(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(ApplicationInsightsManagementClient, provider)
        self.components = self.__get_components__()

    def __get_components__(self):
        logger.info("AppInsights - Getting components...")
        components = {}

        for subscription_name, client in self.clients.items():
            try:
                components_list = client.components.list()
                components.update({subscription_name: {}})

                for component in components_list:
                    components[subscription_name].update(
                        {
                            component.app_id: Component(
                                resource_id=component.id, resource_name=component.name
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return components


@dataclass
class Component:
    resource_id: str
    resource_name: str
