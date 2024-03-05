from dataclasses import dataclass

from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import LogSettings

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Monitor
class Monitor(AzureService):
    def __init__(self, audit_info):
        super().__init__(MonitorManagementClient, audit_info)

        self.diagnostics_settings = self.__get_diagnostics_settings__()
        self.diagnostics_settings_for_key_vault = (
            self.__get_diagnostics_settings_for_key_vault__(audit_info)
        )

    def __get_diagnostics_settings__(self):
        logger.info("Monitor - Getting diagnostics settings...")
        diagnostics_settings = {}
        for subscription, client in self.clients.items():
            try:
                diagnostics_settings.update({subscription: []})
                settings = client.diagnostic_settings.list(
                    resource_uri=f"subscriptions/{self.subscriptions[subscription]}/"
                )
                for setting in settings:
                    diagnostics_settings[subscription].append(
                        DiagnosticSetting(
                            id=setting.id,
                            storage_account_name=setting.storage_account_id.split("/")[
                                -1
                            ],
                            logs=setting.logs,
                            storage_account_id=setting.storage_account_id,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return diagnostics_settings

    def __get_diagnostics_settings_for_key_vault__(self, audit_info):
        logger.info("Monitor - Getting diagnostics settings for key vault...")
        diagnostics_settings_for_key_vault = {}
        for subscription, client in self.clients.items():
            keyvault_client = KeyVaultManagementClient(
                credential=audit_info.credentials,
                subscription_id=self.subscriptions[subscription],
            )
            keyvault_list = keyvault_client.vaults.list()
            try:
                diagnostics_settings_for_key_vault.update({subscription: []})
                for key in keyvault_list:
                    resource_group = key.id.split("/")[4]
                    keyvault_name = key.name
                    settings = client.diagnostic_settings.list(
                        resource_uri=f"subscriptions/{self.subscriptions[subscription]}/resourceGroups/{resource_group}/providers/Microsoft.KeyVault/vaults/{keyvault_name}"
                    )
                    for setting in settings:
                        diagnostics_settings_for_key_vault[subscription].append(
                            DiagnosticSettingForKeyVault(
                                id=setting.id,
                                storage_account_name=setting.storage_account_id.split(
                                    "/"
                                )[-1],
                                logs=setting.logs,
                                storage_account_id=setting.storage_account_id,
                                type=setting.type,
                                key_vault_name=keyvault_name,
                                resource_group=resource_group,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return diagnostics_settings_for_key_vault


@dataclass
class DiagnosticSetting:
    id: str
    storage_account_id: str
    storage_account_name: str
    logs: LogSettings


@dataclass
class DiagnosticSettingForKeyVault:
    id: str
    storage_account_id: str
    storage_account_name: str
    logs: LogSettings
    type: str
    key_vault_name: str
    resource_group: str
