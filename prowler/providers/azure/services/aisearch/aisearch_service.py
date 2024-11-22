from dataclasses import dataclass

from azure.mgmt.search import SearchManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class AISearch(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(SearchManagementClient, provider)
        self.aisearch_services = self._get_aisearch_services()

    def _get_aisearch_services(self):
        logger.info("AISearch - Getting services ...")
        aisearch_services = {}
        for subscription, client in self.clients.items():
            try:
                aisearch_services.update({subscription: {}})
                aisearch_services_list = client.services.list_by_subscription()
                for aisearch_service in aisearch_services_list:
                    aisearch_services[subscription].update(
                        {
                            aisearch_service.id: AISearchService(
                                name=aisearch_service.name,
                                location=aisearch_service.location,
                                public_network_access=(
                                    False
                                    if aisearch_service.public_network_access
                                    == "Disabled"
                                    else True
                                ),
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return aisearch_services


@dataclass
class AISearchService:
    name: str
    location: str
    public_network_access: bool
