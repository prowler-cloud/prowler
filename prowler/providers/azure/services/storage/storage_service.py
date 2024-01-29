from dataclasses import dataclass

from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.v2022_09_01.models import NetworkRuleSet
from azure.mgmt.storage.v2023_01_01.models import PrivateEndpointConnection

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Storage
class Storage(AzureService):
    def __init__(self, audit_info):
        super().__init__(StorageManagementClient, audit_info)
        self.storage_accounts = self.__get_storage_accounts__()

    def __get_storage_accounts__(self):
        logger.info("Storage - Getting storage accounts...")
        storage_accounts = {}
        for subscription, client in self.clients.items():
            try:
                storage_accounts.update({subscription: []})
                storage_accounts_list = client.storage_accounts.list()
                for storage_account in storage_accounts_list:
                    storage_accounts[subscription].append(
                        Storage_Account(
                            id=storage_account.id,
                            name=storage_account.name,
                            enable_https_traffic_only=storage_account.enable_https_traffic_only,
                            infrastructure_encryption=storage_account.encryption.require_infrastructure_encryption,
                            allow_blob_public_access=storage_account.allow_blob_public_access,
                            network_rule_set=storage_account.network_rule_set,
                            encryption_type=storage_account.encryption.key_source,
                            minimum_tls_version=storage_account.minimum_tls_version,
                            private_endpoint_connections=storage_account.private_endpoint_connections,
                        )
                    )
            except Exception as error:
                logger.error(f"Subscription name: {subscription}")
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return storage_accounts


@dataclass
class Storage_Account:
    id: str
    name: str
    enable_https_traffic_only: bool
    infrastructure_encryption: bool
    allow_blob_public_access: bool
    network_rule_set: NetworkRuleSet
    encryption_type: str
    minimum_tls_version: str
    private_endpoint_connections: PrivateEndpointConnection = None
