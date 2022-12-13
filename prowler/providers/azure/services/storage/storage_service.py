from dataclasses import dataclass

from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.v2022_09_01.models import NetworkRuleSet

from prowler.lib.logger import logger


########################## Storage
class Storage:
    def __init__(self, audit_info):
        self.service = "storage"
        self.credentials = audit_info.credentials
        self.subscriptions = audit_info.identity.subscriptions
        self.clients = self.__set_clients__(
            audit_info.identity.subscriptions, audit_info.credentials
        )
        self.storage_accounts = self.__get_storage_accounts__()
        self.region = "azure"

    def __set_clients__(self, subscriptions, credentials):
        clients = {}
        try:
            for display_name, id in subscriptions.items():
                clients.update(
                    {
                        display_name: StorageManagementClient(
                            credential=credentials, subscription_id=id
                        )
                    }
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            return clients

    def __get_storage_accounts__(self):
        logger.info("Storage - Getting storage accounts...")
        storage_accounts = {}
        try:
            for subscription, client in self.clients.items():
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
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
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

    def __init__(
        self,
        id,
        name,
        enable_https_traffic_only,
        infrastructure_encryption,
        allow_blob_public_access,
        network_rule_set,
        encryption_type,
        minimum_tls_version,
    ):
        self.id = id
        self.name = name
        self.enable_https_traffic_only = enable_https_traffic_only
        self.infrastructure_encryption = infrastructure_encryption
        self.allow_blob_public_access = allow_blob_public_access
        self.network_rule_set = network_rule_set
        self.encryption_type = encryption_type
        self.minimum_tls_version = minimum_tls_version
