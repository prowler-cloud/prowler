from dataclasses import dataclass, field
from typing import List, Optional

from azure.mgmt.cosmosdb import CosmosDBManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class CosmosDB(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(CosmosDBManagementClient, provider)
        self.accounts = self._get_accounts()

    def _get_accounts(self):
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
                            private_endpoint_connections=[
                                PrivateEndpointConnection(
                                    id=private_endpoint_connection.id,
                                    name=private_endpoint_connection.name,
                                    type=private_endpoint_connection.type,
                                )
                                for private_endpoint_connection in getattr(
                                    account, "private_endpoint_connections", []
                                )
                                if private_endpoint_connection
                            ],
                            disable_local_auth=getattr(
                                account, "disable_local_auth", False
                            ),
                            enable_automatic_failover=getattr(
                                account, "enable_automatic_failover", False
                            ),
                            backup_policy_type=getattr(
                                getattr(account, "backup_policy", None),
                                "type",
                                None,
                            ),
                            public_network_access=getattr(
                                account, "public_network_access", None
                            ),
                            minimal_tls_version=getattr(
                                account, "minimal_tls_version", None
                            ),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return accounts


@dataclass
class PrivateEndpointConnection:
    id: str
    name: str
    type: str


@dataclass
class Account:
    id: str
    name: str
    kind: str
    type: str
    tags: dict
    is_virtual_network_filter_enabled: bool
    location: str
    private_endpoint_connections: List[PrivateEndpointConnection]
    disable_local_auth: bool = False
    enable_automatic_failover: bool = False
    backup_policy_type: Optional[str] = None
    public_network_access: Optional[str] = None
    minimal_tls_version: Optional[str] = None
