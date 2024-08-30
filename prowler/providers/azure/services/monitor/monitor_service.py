from dataclasses import dataclass

from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import AlertRuleAllOfCondition, LogSettings

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


########################## Monitor
class Monitor(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(MonitorManagementClient, provider)

        self.diagnostics_settings = self._get_diagnostics_settings()
        self.alert_rules = self.get_alert_rules()

    def _get_diagnostics_settings(self):
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
                        storage_account_name=(
                            setting.storage_account_id.split("/")[-1]
                            if getattr(setting, "storage_account_id", None)
                            else None
                        ),
                        logs=setting.logs,
                        storage_account_id=setting.storage_account_id,
                    )
                )
        except Exception as error:
            logger.error(
                f"Subscription id: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
    name: str


@dataclass
class AlertRule:
    id: str
    name: str
    condition: AlertRuleAllOfCondition
    enabled: bool
    description: str
