from dataclasses import dataclass

from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import AlertRuleAllOfCondition, LogSettings

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Monitor
class Monitor(AzureService):
    def __init__(self, audit_info):
        super().__init__(MonitorManagementClient, audit_info)

        self.diagnostics_settings = self.__get_diagnostics_settings__()
        self.alert_rules = self.get_alert_rules()

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

    def get_alert_rules(self):
        logger.info("Monitor - Getting alert rules...")
        alert_rules = {}
        for subscription, client in self.clients.items():
            try:
                alert_rules.update({subscription: []})
                rules = client.activity_log_alerts.list_by_subscription_id()
                for rule in rules:
                    alert_rules[subscription].append(
                        AlertRule(
                            id=rule.id,
                            name=rule.name,
                            condition=rule.condition,
                            enabled=rule.enabled,
                            description=rule.description,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return alert_rules


@dataclass
class DiagnosticSetting:
    id: str
    storage_account_id: str
    storage_account_name: str
    logs: LogSettings


@dataclass
class AlertRule:
    id: str
    name: str
    condition: AlertRuleAllOfCondition
    enabled: bool
    description: str
