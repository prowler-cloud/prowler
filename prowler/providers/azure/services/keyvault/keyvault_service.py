from dataclasses import dataclass

from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.keyvault.v2023_07_01.models import KeyAttributes, VaultProperties

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Storage
class KeyVault(AzureService):
    def __init__(self, audit_info):
        super().__init__(KeyVaultManagementClient, audit_info)
        self.keyvaults = self.__get_keyvaults__()

    def __get_keyvaults__(self):
        logger.info("KeyVault - Getting keyvaults...")
        keyvaults = {}
        for subscription, client in self.clients.items():
            try:
                keyvaults.update({subscription: []})
                keyvaults_list = client.vaults.list()
                for keyvault in keyvaults_list:
                    resource_group = keyvault.id.split("/")[4]
                    keyvault_name = keyvault.name
                    keyvault_properties = client.vaults.get(
                        resource_group, keyvault_name
                    ).properties
                    keyvaults[subscription].append(
                        KeyVaultInfo(
                            name=keyvault_name,
                            location=keyvault.location,
                            resource_group=resource_group,
                            properties=keyvault_properties,
                            keys=[
                                Key(
                                    name=key.name,
                                    enabled=key.attributes.enabled,
                                    location=key.location,
                                    attributes=key.attributes,
                                )
                                for key in client.keys.list(
                                    resource_group, keyvault_name
                                )
                            ],
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return keyvaults


@dataclass
class Key:
    name: str
    enabled: bool
    location: str
    attributes: KeyAttributes


@dataclass
class KeyVaultInfo:
    name: str
    location: str
    resource_group: str
    properties: VaultProperties
    keys: list[Key]
