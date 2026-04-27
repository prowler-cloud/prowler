from azure.mgmt.applicationinsights import ApplicationInsightsManagementClient
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class AppInsights(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(ApplicationInsightsManagementClient, provider)
        self.components = self._get_components()

    def _get_components(self):
        logger.info("AppInsights - Getting components...")
        components = {}

        for subscription_name, client in self.clients.items():
            try:
                components_list = []
                components.update({subscription_name: {}})

                if self.resource_groups:
                    rgs = self.resource_groups.get(subscription_name, [])
                    if not rgs:
                        logger.warning(
                            f"No valid resource groups for subscription {subscription_name}"
                        )
                    else:
                        for rg in rgs:
                            try:
                                components_list += list(
                                    client.components.list_by_resource_group(
                                        resource_group_name=rg
                                    )
                                )
                            except Exception as error:
                                logger.warning(
                                    f"Subscription name: {subscription_name} -- Resource Group: {rg} -- "
                                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                else:
                    components_list = client.components.list()

                for component in components_list:
                    components[subscription_name].update(
                        {
                            component.app_id: Component(
                                resource_id=component.id,
                                resource_name=component.name,
                                location=component.location,
                                instrumentation_key=getattr(
                                    component, "instrumentation_key", "Not Found"
                                ),
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return components


class Component(BaseModel):
    resource_id: str
    resource_name: str
    location: str
    instrumentation_key: str
