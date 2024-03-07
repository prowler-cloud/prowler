from dataclasses import dataclass

from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import LogSettings

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Monitor
class Monitor(AzureService):
    def __init__(self, audit_info):
        super().__init__(MonitorManagementClient, audit_info)

        self.diagnostics_settings = self.__get_diagnostics_settings__()

    def __get_diagnostics_settings__(self):
        logger.info("Monitor - Getting diagnostics settings...")
        diagnostics_settings_list = []
        diagnostics_settings = {}
        for subscription, client in self.clients.items():
            try:
                diagnostics_settings_list = self.diagnostic_settings_with_uri(
                    subscription,
                    f"subscriptions/{self.subscriptions[subscription]}/",
                    client,
                )
                diagnostics_settings.update({subscription: diagnostics_settings_list})
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return diagnostics_settings

    def diagnostic_settings_with_uri(self, subscription, uri, client):
        diagnostics_settings = []
        try:
            settings = client.diagnostic_settings.list(resource_uri=uri)
            for setting in settings:
                diagnostics_settings.append(
                    DiagnosticSetting(
                        id=setting.id,
                        name=setting.id.split("/")[-1],
                        storage_account_name=setting.storage_account_id.split("/")[-1],
                        logs=setting.logs,
                        storage_account_id=setting.storage_account_id,
                    )
                )
        except Exception as error:
            logger.error(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return diagnostics_settings


@dataclass
class DiagnosticSetting:
    id: str
    storage_account_id: str
    storage_account_name: str
    logs: LogSettings
    name: str
