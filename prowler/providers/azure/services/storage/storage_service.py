from dataclasses import dataclass

from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.v2022_09_01.models import (
    DeleteRetentionPolicy,
    NetworkRuleSet,
    PrivateEndpointConnection,
)

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Storage
class Storage(AzureService):
    def __init__(self, audit_info):
        super().__init__(StorageManagementClient, audit_info)
        self.storage_accounts = self.__get_storage_accounts__()
        self.__get_blob_properties__()

    def __get_storage_accounts__(self):
        logger.info("Storage - Getting storage accounts...")
        storage_accounts = {}
        for subscription, client in self.clients.items():
            try:
                storage_accounts.update({subscription: []})
                storage_accounts_list = client.storage_accounts.list()
                for storage_account in storage_accounts_list:
                    parts = storage_account.id.split("/")
                    if "resourceGroups" in parts:
                        resouce_name_index = parts.index("resourceGroups") + 1
                        resouce_group_name = parts[resouce_name_index]
                    else:
                        resouce_group_name = None
                    key_expiration_period_in_days = None
                    if storage_account.key_policy:
                        key_expiration_period_in_days = (
                            storage_account.key_policy.key_expiration_period_in_days
                        )
                    storage_accounts[subscription].append(
                        Account(
                            id=storage_account.id,
                            name=storage_account.name,
                            resouce_group_name=resouce_group_name,
                            enable_https_traffic_only=storage_account.enable_https_traffic_only,
                            infrastructure_encryption=storage_account.encryption.require_infrastructure_encryption,
                            allow_blob_public_access=storage_account.allow_blob_public_access,
                            network_rule_set=storage_account.network_rule_set,
                            encryption_type=storage_account.encryption.key_source,
                            minimum_tls_version=storage_account.minimum_tls_version,
                            private_endpoint_connections=storage_account.private_endpoint_connections,
                            key_expiration_period_in_days=key_expiration_period_in_days,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return storage_accounts

    def __get_blob_properties__(self):
        logger.info("Storage - Getting blob properties...")
        try:
            for subscription, accounts in self.storage_accounts.items():
                client = self.clients[subscription]
                for account in accounts:
                    properties = client.blob_services.get_service_properties(
                        account.resouce_group_name, account.name
                    )
                    account.blob_properties = BlobProperties(
                        id=properties.id,
                        name=properties.name,
                        type=properties.type,
                        default_service_version=properties.default_service_version,
                        container_delete_retention_policy=properties.container_delete_retention_policy,
                    )
        except Exception as error:
            logger.error(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class BlobProperties:
    id: str
    name: str
    type: str
    default_service_version: str
    container_delete_retention_policy: DeleteRetentionPolicy


@dataclass
class Account:
    id: str
    name: str
    resouce_group_name: str
    enable_https_traffic_only: bool
    infrastructure_encryption: bool
    allow_blob_public_access: bool
    network_rule_set: NetworkRuleSet
    encryption_type: str
    minimum_tls_version: str
    private_endpoint_connections: PrivateEndpointConnection
    key_expiration_period_in_days: str
    blob_properties: BlobProperties = None
