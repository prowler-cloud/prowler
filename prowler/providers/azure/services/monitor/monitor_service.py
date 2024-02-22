from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import LogSettings
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Monitor
class Monitor(AzureService):
    def __init__(self, audit_info):
        super().__init__(MonitorManagementClient, audit_info)

        self.diagnostics_settings = self.__get_diagnostics_settings__()

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
                            logs=setting.logs,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return diagnostics_settings


# @dataclass
# class DiagnosticSetting:
#    id: str
#    logs: list


class DiagnosticSetting(BaseModel):
    id: str
    logs: LogSettings
