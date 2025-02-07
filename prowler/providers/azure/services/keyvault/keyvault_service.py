from dataclasses import dataclass
from datetime import datetime
from typing import List, Union

from azure.core.exceptions import HttpResponseError
from azure.keyvault.keys import KeyClient
from azure.mgmt.keyvault import KeyVaultManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService
from prowler.providers.azure.services.monitor.monitor_client import monitor_client
from prowler.providers.azure.services.monitor.monitor_service import DiagnosticSetting


class KeyVault(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(KeyVaultManagementClient, provider)
        # TODO: review this credentials assignment
        self.key_vaults = self._get_key_vaults(provider)

    def _get_key_vaults(self, provider):
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
                    keys = self._get_keys(
                        subscription, resource_group, keyvault_name, provider
                    )
                    secrets = self._get_secrets(
                        subscription, resource_group, keyvault_name
                    )
                    key_vaults[subscription].append(
                        KeyVaultInfo(
                            id=getattr(keyvault, "id", ""),
                            name=getattr(keyvault, "name", ""),
                            location=getattr(keyvault, "location", ""),
                            resource_group=resource_group,
                            properties=VaultProperties(
                                tenant_id=getattr(keyvault_properties, "tenant_id", ""),
                                enable_rbac_authorization=getattr(
                                    keyvault_properties,
                                    "enable_rbac_authorization",
                                    False,
                                ),
                                private_endpoint_connections=[
                                    PrivateEndpointConnection(id=conn.id)
                                    for conn in getattr(
                                        keyvault_properties,
                                        "private_endpoint_connections",
                                        [],
                                    )
                                ],
                                enable_soft_delete=getattr(
                                    keyvault_properties, "enable_soft_delete", False
                                ),
                                enable_purge_protection=getattr(
                                    keyvault_properties,
                                    "enable_purge_protection",
                                    False,
                                ),
                            ),
                            keys=keys,
                            secrets=secrets,
                            monitor_diagnostic_settings=self._get_vault_monitor_settings(
                                keyvault_name, resource_group, subscription
                            ),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return key_vaults

    def _get_keys(self, subscription, resource_group, keyvault_name, provider):
        logger.info(f"KeyVault - Getting keys for {keyvault_name}...")
        keys = []
        try:
            client = self.clients[subscription]
            keys_list = client.keys.list(resource_group, keyvault_name)
            for key in keys_list:
                keys.append(
                    Key(
                        id=getattr(key, "id", ""),
                        name=getattr(key, "name", ""),
                        enabled=getattr(key.attributes, "enabled", False),
                        location=getattr(key, "location", ""),
                        attributes=KeyAttributes(
                            enabled=getattr(key.attributes, "enabled", False),
                            created=getattr(key.attributes, "created", 0),
                            updated=getattr(key.attributes, "updated", 0),
                            expires=getattr(key.attributes, "expires", 0),
                        ),
                    )
                )
        except Exception as error:
            logger.error(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        try:
            key_client = KeyClient(
                vault_url=f"https://{keyvault_name}.vault.azure.net/",
                # TODO: review the following line
                credential=provider.session,
            )
            properties = key_client.list_properties_of_keys()
            for prop in properties:
                policy = key_client.get_key_rotation_policy(prop.name)
                for key in keys:
                    if key.name == prop.name:
                        key.rotation_policy = policy

        # TODO: handle different errors here since we are catching all HTTP Errors here
        except HttpResponseError:
            logger.error(
                f"Subscription name: {subscription} -- has no access policy configured for keyvault {keyvault_name}"
            )
        return keys

    def _get_secrets(self, subscription, resource_group, keyvault_name):
        logger.info(f"KeyVault - Getting secrets for {keyvault_name}...")
        secrets = []
        try:
            client = self.clients[subscription]
            secrets_list = client.secrets.list(resource_group, keyvault_name)
            for secret in secrets_list:
                secrets.append(
                    Secret(
                        id=getattr(secret, "id", ""),
                        name=getattr(secret, "name", ""),
                        enabled=getattr(secret.properties.attributes, "enabled", False),
                        location=getattr(secret, "location", ""),
                        attributes=SecretAttributes(
                            enabled=getattr(
                                secret.properties.attributes, "enabled", False
                            ),
                            created=getattr(
                                secret.properties.attributes, "created", None
                            ),
                            updated=getattr(
                                secret.properties.attributes, "updated", None
                            ),
                            expires=getattr(
                                secret.properties.attributes, "expires", None
                            ),
                        ),
                    )
                )
        except Exception as error:
            logger.error(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return secrets

    def _get_vault_monitor_settings(self, keyvault_name, resource_group, subscription):
        logger.info(
            f"KeyVault - Getting monitor diagnostics settings for {keyvault_name}..."
        )
        monitor_diagnostics_settings = []
        try:
            monitor_diagnostics_settings = monitor_client.diagnostic_settings_with_uri(
                self.subscriptions[subscription],
                f"subscriptions/{self.subscriptions[subscription]}/resourceGroups/{resource_group}/providers/Microsoft.KeyVault/vaults/{keyvault_name}",
                monitor_client.clients[subscription],
            )
        except Exception as error:
            logger.error(
                f"Subscription name: {self.subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return monitor_diagnostics_settings


@dataclass
class KeyAttributes:
    enabled: bool
    created: int
    updated: int
    expires: int


@dataclass
class Key:
    id: str
    name: str
    enabled: bool
    location: str
    attributes: KeyAttributes
    rotation_policy: str = None


@dataclass
class SecretAttributes:
    enabled: bool
    created: Union[datetime, None]
    updated: Union[datetime, None]
    expires: Union[datetime, None]


@dataclass
class Secret:
    id: str
    name: str
    enabled: bool
    location: str
    attributes: SecretAttributes


@dataclass
class PrivateEndpointConnection:
    id: str


@dataclass
class VaultProperties:
    tenant_id: str
    enable_rbac_authorization: bool
    private_endpoint_connections: List[PrivateEndpointConnection]
    enable_soft_delete: bool
    enable_purge_protection: bool


@dataclass
class KeyVaultInfo:
    id: str
    name: str
    location: str
    resource_group: str
    properties: VaultProperties
    keys: list[Key] = None
    secrets: list[Secret] = None
    monitor_diagnostic_settings: list[DiagnosticSetting] = None
