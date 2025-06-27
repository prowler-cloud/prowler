from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from azure.mgmt.storage import StorageManagementClient
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class Storage(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(StorageManagementClient, provider)
        self.storage_accounts = self._get_storage_accounts()
        self._get_blob_properties()
        self._get_file_share_properties()

    def _get_storage_accounts(self):
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
                    replication_settings = ReplicationSettings(storage_account.sku.name)
                    storage_accounts[subscription].append(
                        Account(
                            id=storage_account.id,
                            name=storage_account.name,
                            resouce_group_name=resouce_group_name,
                            enable_https_traffic_only=storage_account.enable_https_traffic_only,
                            infrastructure_encryption=storage_account.encryption.require_infrastructure_encryption,
                            allow_blob_public_access=storage_account.allow_blob_public_access,
                            network_rule_set=NetworkRuleSet(
                                bypass=getattr(
                                    storage_account.network_rule_set,
                                    "bypass",
                                    "AzureServices",
                                ),
                                default_action=getattr(
                                    storage_account.network_rule_set,
                                    "default_action",
                                    "Allow",
                                ),
                            ),
                            encryption_type=storage_account.encryption.key_source,
                            minimum_tls_version=storage_account.minimum_tls_version,
                            private_endpoint_connections=[
                                PrivateEndpointConnection(
                                    id=pec.id,
                                    name=pec.name,
                                    type=pec.type,
                                )
                                for pec in getattr(
                                    storage_account, "private_endpoint_connections", []
                                )
                            ],
                            key_expiration_period_in_days=key_expiration_period_in_days,
                            location=storage_account.location,
                            default_to_entra_authorization=getattr(
                                storage_account,
                                "default_to_o_auth_authentication",
                                False,
                            ),
                            replication_settings=replication_settings,
                            allow_cross_tenant_replication=getattr(
                                storage_account, "allow_cross_tenant_replication", True
                            ),
                            allow_shared_key_access=getattr(
                                storage_account, "allow_shared_key_access", True
                            ),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return storage_accounts

    def _get_blob_properties(self):
        logger.info("Storage - Getting blob properties...")
        try:
            for subscription, accounts in self.storage_accounts.items():
                client = self.clients[subscription]
                for account in accounts:
                    try:
                        properties = client.blob_services.get_service_properties(
                            account.resouce_group_name, account.name
                        )
                        container_delete_retention_policy = getattr(
                            properties, "container_delete_retention_policy", None
                        )
                        versioning_enabled = getattr(
                            properties, "is_versioning_enabled", False
                        )
                        account.blob_properties = BlobProperties(
                            id=properties.id,
                            name=properties.name,
                            type=properties.type,
                            default_service_version=properties.default_service_version,
                            container_delete_retention_policy=DeleteRetentionPolicy(
                                enabled=getattr(
                                    container_delete_retention_policy,
                                    "enabled",
                                    False,
                                ),
                                days=getattr(
                                    container_delete_retention_policy, "days", 0
                                ),
                            ),
                            versioning_enabled=versioning_enabled,
                        )
                    except Exception as error:
                        if (
                            "Blob is not supported for the account."
                            in str(error).strip()
                        ):
                            logger.warning(
                                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
                            continue
                        logger.error(
                            f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )

        except Exception as error:
            logger.error(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_file_share_properties(self):
        logger.info("Storage - Getting file share properties...")
        for subscription, accounts in self.storage_accounts.items():
            client = self.clients[subscription]
            for account in accounts:
                try:
                    file_service_properties = (
                        client.file_services.get_service_properties(
                            account.resouce_group_name, account.name
                        )
                    )
                    share_delete_retention_policy = getattr(
                        file_service_properties,
                        "share_delete_retention_policy",
                        None,
                    )

                    smb_channel_encryption_raw = getattr(
                        getattr(
                            getattr(
                                file_service_properties,
                                "protocol_settings",
                                None,
                            ),
                            "smb",
                            None,
                        ),
                        "channel_encryption",
                        None,
                    )

                    account.file_service_properties = FileServiceProperties(
                        id=file_service_properties.id,
                        name=file_service_properties.name,
                        type=file_service_properties.type,
                        share_delete_retention_policy=DeleteRetentionPolicy(
                            enabled=getattr(
                                share_delete_retention_policy,
                                "enabled",
                                False,
                            ),
                            days=getattr(
                                share_delete_retention_policy,
                                "days",
                                0,
                            ),
                        ),
                        smb_protocol_settings=SMBProtocolSettings(
                            channel_encryption=(
                                smb_channel_encryption_raw.rstrip(";").split(";")
                                if smb_channel_encryption_raw
                                else []
                            )
                        ),
                    )
                except Exception as error:
                    logger.error(
                        f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )


@dataclass
class DeleteRetentionPolicy:
    enabled: bool
    days: int


@dataclass
class BlobProperties:
    id: str
    name: str
    type: str
    default_service_version: str
    container_delete_retention_policy: DeleteRetentionPolicy
    versioning_enabled: bool = False


@dataclass
class NetworkRuleSet:
    bypass: str
    default_action: str


@dataclass
class PrivateEndpointConnection:
    id: str
    name: str
    type: str


class ReplicationSettings(Enum):
    STANDARD_LRS = "Standard_LRS"
    STANDARD_GRS = "Standard_GRS"
    STANDARD_RAGRS = "Standard_RAGRS"
    STANDARD_ZRS = "Standard_ZRS"
    PREMIUM_LRS = "Premium_LRS"
    PREMIUM_ZRS = "Premium_ZRS"
    STANDARD_GZRS = "Standard_GZRS"
    STANDARD_RAGZRS = "Standard_RAGZRS"


class SMBProtocolSettings(BaseModel):
    channel_encryption: list[str]


class FileServiceProperties(BaseModel):
    id: str
    name: str
    type: str
    share_delete_retention_policy: DeleteRetentionPolicy
    smb_protocol_settings: SMBProtocolSettings


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
    private_endpoint_connections: List[PrivateEndpointConnection]
    key_expiration_period_in_days: str
    location: str
    replication_settings: ReplicationSettings = ReplicationSettings.STANDARD_LRS
    allow_cross_tenant_replication: bool = True
    allow_shared_key_access: bool = True
    blob_properties: Optional[BlobProperties] = None
    default_to_entra_authorization: bool = False
    file_service_properties: Optional[FileServiceProperties] = None
