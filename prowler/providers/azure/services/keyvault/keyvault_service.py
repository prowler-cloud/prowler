from dataclasses import dataclass

from azure.core.exceptions import HttpResponseError
from azure.keyvault.keys import KeyClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.keyvault.v2023_07_01.models import (
    KeyAttributes,
    SecretAttributes,
    VaultProperties,
)

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Storage
class KeyVault(AzureService):
    def __init__(self, audit_info):
        super().__init__(KeyVaultManagementClient, audit_info)
        self.key_vaults = self.__get_key_vaults__(audit_info)

    def __get_key_vaults__(self, audit_info):
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
                        subscription, resource_group, keyvault_name, audit_info
                    )
                    secrets = self.__get_secrets__(
                        subscription, resource_group, keyvault_name
                    )
                    key_vaults[subscription].append(
                        KeyVaultInfo(
                            id=getattr(keyvault, "id", None),
                            name=getattr(keyvault, "name", None),
                            location=getattr(keyvault, "location", None),
                            resource_group=resource_group,
                            properties=keyvault_properties,
                            keys=keys,
                            secrets=secrets,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return key_vaults

    def __get_keys__(self, subscription, resource_group, keyvault_name, audit_info):
        logger.info(f"KeyVault - Getting keys for {keyvault_name}...")
        keys = []
        try:
            client = self.clients[subscription]
            keys_list = client.keys.list(resource_group, keyvault_name)
            for key in keys_list:
                keys.append(
                    Key(
                        id=getattr(key, "id", None),
                        name=getattr(key, "name", None),
                        enabled=getattr(key.attributes, "enabled", None),
                        location=getattr(key, "location", None),
                        attributes=getattr(key, "attributes", None),
                        rotation_policy=None,
                    )
                )
        except Exception as error:
            logger.error(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        try:
            key_client = KeyClient(
                vault_url=f"https://{keyvault_name}.vault.azure.net/",
                credential=audit_info.credentials,
            )
            properties = key_client.list_properties_of_keys()
            for prop in properties:
                policy = key_client.get_key_rotation_policy(prop.name)
                for key in keys:
                    if key.name == prop.name:
                        key.rotation_policy = policy

        except HttpResponseError:
            logger.error(
                f"Subscription name: {subscription} -- has no access policy configured for keyvault {keyvault_name}"
            )
        return keys

    def __get_secrets__(self, subscription, resource_group, keyvault_name):
        logger.info(f"KeyVault - Getting secrets for {keyvault_name}...")
        secrets = []
        try:
            client = self.clients[subscription]
            secrets_list = client.secrets.list(resource_group, keyvault_name)
            for secret in secrets_list:
                secrets.append(
                    Secret(
                        id=getattr(secret, "id", None),
                        name=getattr(secret, "name", None),
                        enabled=getattr(secret.properties.attributes, "enabled", None),
                        location=getattr(secret, "location", None),
                        attributes=getattr(secret.properties, "attributes", None),
                    )
                )
        except Exception as error:
            logger.error(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return secrets


@dataclass
class Key:
    id: str
    name: str
    enabled: bool
    location: str
    attributes: KeyAttributes
    rotation_policy: str = None


@dataclass
class Secret:
    id: str
    name: str
    enabled: bool
    location: str
    attributes: SecretAttributes


@dataclass
class KeyVaultInfo:
    id: str
    name: str
    location: str
    resource_group: str
    properties: VaultProperties
    keys: list[Key] = None
    secrets: list[Secret] = None
