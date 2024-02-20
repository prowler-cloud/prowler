from dataclasses import dataclass

from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.keyvault.v2023_07_01.models import KeyAttributes, VaultProperties

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Storage
class KeyVault(AzureService):
    def __init__(self, audit_info):
        super().__init__(KeyVaultManagementClient, audit_info)
        self.key_vaults = self.__get_key_vaults__()

    def __get_key_vaults__(self):
        logger.info("KeyVault - Getting key_vaults...")
        key_vaults = {}
        for subscription, client in self.clients.items():
            try:
                key_vaults.update({subscription: []})
                key_vaults_list = client.vaults.list()
                for keyvault in key_vaults_list:
                    resource_group = keyvault.id.split("/")[4]
                    keyvault_name = keyvault.name
                    keyvault_properties = client.vaults.get(
                        resource_group, keyvault_name
                    ).properties
                    keys = self.__get_keys__(
                        subscription, resource_group, keyvault_name
                    )
                    key_vaults[subscription].append(
                        KeyVaultInfo(
                            id=keyvault.id,
                            name=keyvault_name,
                            location=keyvault.location,
                            resource_group=resource_group,
                            properties=keyvault_properties,
                            keys=keys,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return key_vaults

    def __get_keys__(self, subscription, resource_group, keyvault_name):
        logger.info(f"KeyVault - Getting keys for {keyvault_name}...")
        keys = []
        try:
            client = self.clients[subscription]
            keys_list = client.keys.list(resource_group, keyvault_name)
            for key in keys_list:
                keys.append(
                    Key(
                        id=key.id,
                        name=key.name,
                        enabled=key.properties.enabled,
                        location=key.location,
                        attributes=key.properties,
                    )
                )
        except Exception as error:
            logger.error(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return keys


@dataclass
class Key:
    id: str
    name: str
    enabled: bool
    location: str
    attributes: KeyAttributes


@dataclass
class KeyVaultInfo:
    id: str
    name: str
    location: str
    resource_group: str
    properties: VaultProperties
    keys: list[Key] = None
