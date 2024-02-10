from dataclasses import dataclass

from azure.mgmt.cosmosdb import CosmosDBManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


class CosmosDB(AzureService):
    def __init__(self, audit_info):
        super().__init__(CosmosDBManagementClient, audit_info)
        self.accounts = self.__get_accounts__()

    def __get_accounts__(self):
        logger.info("CosmosDB - Getting accounts...")
        accounts = {}
        for subscription, client in self.clients.items():
            try:
                accounts_list = client.database_accounts.list()
                accounts.update({subscription: []})
                for account in accounts_list:
                    accounts[subscription].append(
                        Account(
                            id=account.id,
                            name=account.name,
                            kind=account.kind,
                            location=account.location,
                            type=account.type,
                            tags=account.tags,
                            is_virtual_network_filter_enabled=account.is_virtual_network_filter_enabled,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return accounts


@dataclass
class Account:
    id: str
    name: str
    kind: str
    location: str
    type: str
    tags: dict
    is_virtual_network_filter_enabled: bool
