from dataclasses import dataclass

from azure.mgmt.search import SearchManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class AISearch(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(SearchManagementClient, provider)
        self.search_services = self._get_search_services()

    def _get_search_services(self):
        logger.info("Search - Getting services ...")
        search_services = {}
        for subscription, client in self.clients.items():
            try:
                search_services.update({subscription: {}})
                search_services_list = client.services.list_by_subscription()
                for search_service in search_services_list:
                    search_services[subscription].append(
                        SearchService(
                            id=search_service.id,
                            name=search_service.name,
                            location=search_service.location,
                            public_network_access=getattr(
                                search_service, "public_network_access", True
                            ),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return search_services


@dataclass
class SearchService:
    id: str
    name: str
    location: str
    public_network_access: bool
