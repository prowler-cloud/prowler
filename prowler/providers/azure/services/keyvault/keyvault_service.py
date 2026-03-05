from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Union

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
        """
        Get all KeyVaults with parallel processing.

        Optimizations:
        1. Uses list_by_subscription() for full Vault objects
        2. Processes vaults in parallel using __threading_call__
        3. Each vault's keys/secrets/monitor fetched in parallel
        """
        logger.info("KeyVault - Getting key_vaults...")
        key_vaults = {}

        for subscription, client in self.clients.items():
            try:
                key_vaults[subscription] = []
                vaults_list = list(client.vaults.list_by_subscription())

                if not vaults_list:
                    continue

                # Prepare items for parallel processing
                items = [
                    {
                        "subscription": subscription,
                        "keyvault": vault,
                        "provider": provider,
                    }
                    for vault in vaults_list
                ]

                # Process all KeyVaults in parallel
                results = self.__threading_call__(self._process_single_keyvault, items)
                key_vaults[subscription] = results

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return key_vaults

    def _process_single_keyvault(self, item: dict) -> Optional["KeyVaultInfo"]:
        """Process a single KeyVault in parallel."""
        subscription = item["subscription"]
        keyvault = item["keyvault"]
        provider = item["provider"]

        try:
            resource_group = keyvault.id.split("/")[4]
            keyvault_name = keyvault.name
            keyvault_properties = keyvault.properties

            # Fetch keys, secrets, and monitor in parallel
            with ThreadPoolExecutor(max_workers=3) as executor:
                keys_future = executor.submit(
                    self._get_keys,
                    subscription,
                    resource_group,
                    keyvault_name,
                    provider,
                )
                secrets_future = executor.submit(
                    self._get_secrets, subscription, resource_group, keyvault_name
                )
                monitor_future = executor.submit(
                    self._get_vault_monitor_settings,
                    keyvault_name,
                    resource_group,
                    subscription,
                )

                keys = keys_future.result()
                secrets = secrets_future.result()
                monitor_settings = monitor_future.result()

            return KeyVaultInfo(
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
                        for conn in (
                            getattr(
                                keyvault_properties,
                                "private_endpoint_connections",
                                [],
                            )
                            or []
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
                    public_network_access_disabled=(
                        getattr(
                            keyvault_properties,
                            "public_network_access",
                            "Enabled",
                        )
                        == "Disabled"
                    ),
                ),
                keys=keys,
                secrets=secrets,
                monitor_diagnostic_settings=monitor_settings,
            )

        except Exception as error:
            logger.error(
                f"KeyVault {keyvault.name} in {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def _get_keys(self, subscription, resource_group, keyvault_name, provider):
        logger.info(f"KeyVault - Getting keys for {keyvault_name}...")
        keys = []
        keys_dict = {}

        try:
            client = self.clients[subscription]
            keys_list = client.keys.list(resource_group, keyvault_name)
            for key in keys_list:
                key_obj = Key(
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
                keys.append(key_obj)
                keys_dict[key_obj.name] = key_obj

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
            properties = list(key_client.list_properties_of_keys())

            if properties:
                items = [
                    {"key_client": key_client, "prop": prop} for prop in properties
                ]
                rotation_results = self.__threading_call__(
                    self._get_single_rotation_policy, items
                )

                for name, policy in rotation_results:
                    if policy and name in keys_dict:
                        keys_dict[name].rotation_policy = KeyRotationPolicy(
                            id=getattr(policy, "id", ""),
                            lifetime_actions=[
                                KeyRotationLifetimeAction(action=action.action)
                                for action in getattr(policy, "lifetime_actions", [])
                            ],
                        )

        # TODO: handle different errors here since we are catching all HTTP Errors here
        except HttpResponseError:
            logger.warning(
                f"Subscription name: {subscription} -- has no access policy configured for keyvault {keyvault_name}"
            )

        return keys

    def _get_single_rotation_policy(self, item: dict) -> tuple:
        """Thread-safe rotation policy retrieval."""
        key_client = item["key_client"]
        prop = item["prop"]

        try:
            policy = key_client.get_key_rotation_policy(prop.name)
            return (prop.name, policy)
        except HttpResponseError:
            return (prop.name, None)
        except Exception as error:
            logger.warning(
                f"KeyVault - Failed to get rotation policy for key {prop.name}: {error}"
            )
            return (prop.name, None)

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
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return monitor_diagnostics_settings


@dataclass
class KeyAttributes:
    enabled: bool
    created: int
    updated: int
    expires: int


@dataclass
class KeyRotationLifetimeAction:
    action: str


@dataclass
class KeyRotationPolicy:
    id: str
    lifetime_actions: list[KeyRotationLifetimeAction]


@dataclass
class Key:
    id: str
    name: str
    enabled: bool
    location: str
    attributes: KeyAttributes
    rotation_policy: Optional[KeyRotationPolicy] = None


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
    public_network_access_disabled: bool = False


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
