from dataclasses import dataclass

from azure.mgmt.monitor import MonitorManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Monitor
class Monitor(AzureService):
    def __init__(self, audit_info):
        super().__init__(MonitorManagementClient, audit_info)
        # self.activity_logs = self.__get_activity_logs__()
        # self.activity_log_alerts = self.__get_activity_log_alerts__()
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
                            name=setting.name,
                            type=setting.type,
                            event_hub_authorization_rule_id=setting.event_hub_authorization_rule_id,
                            event_hub_name=setting.event_hub_name,
                            metrics=setting.metrics,
                            logs=setting.logs,
                            workspace_id=setting.workspace_id,
                            storage_account_id=setting.storage_account_id,
                            service_bus_rule_id=setting.service_bus_rule_id,
                            marketplace_partner_id=setting.marketplace_partner_id,
                            log_analytics_destination_type=setting.log_analytics_destination_type,
                        )
                    )
                    for i in range(0, 6):
                        print(setting.logs[i].enabled)
                        print(setting.logs[i].category)

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return diagnostics_settings

    # def __get_activity_logs__(self):
    #    logger.info("Monitor - Getting activity logs...")
    #    activity_logs = {}
    #    for subscription, client in self.clients.items():
    #        try:
    #            activity_logs.update({subscription: []})
    #            start_time = datetime.datetime.now() - datetime.timedelta(days=90)
    #            end_time = datetime.datetime.now()
    #            logs = client.activity_logs.list(
    #                filter=f"eventTimestamp ge {start_time.isoformat()} and eventTimestamp le {end_time.isoformat()}"
    #            )
    #            for log in logs:
    #                activity_logs[subscription].append(
    #                    ActivityLog(
    #                        id=log.id,
    #                        resource_group=log.resource_group_name,
    #                        resource_id=log.resource_id,
    #                        operation_name=log.operation_name,
    #                        status=log.status,
    #                        event_timestamp=log.event_timestamp,
    #                        caller=log.caller,
    #                        correlation_id=log.correlation_id,
    #                        category=log.category,
    #                        level=log.level,
    #                        event_data_id=log.event_data_id,
    #                        sub_status=log.sub_status,
    #                    )
    #                )
    #        except Exception as error:
    #            logger.error(
    #                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
    #            )
    #    #print(activity_logs)
    #    print("HOLA")
    #    return activity_logs

    # def __get_activity_log_alerts__(self):
    #    logger.info("Monitor - Getting activity log alerts...")
    #    activity_log_alerts = {}
    #    for subscription, client in self.clients.items():
    #        try:
    #            activity_log_alerts.update({subscription: []})
    #            alerts = client.activity_log_alerts.list_by_subscription_id()
    #            for alert in alerts:
    #                print(alert.condition.all_of[0].equals[0].value)
    #                activity_log_alerts[subscription].append(
    #                    ActivityLogAlert(
    #                        id=alert.id,
    #                        name=alert.name,
    #                        description=alert.description,
    #                        enabled=alert.enabled,
    #                        scopes=alert.scopes,
    #                        condition=alert.condition,
    #                        actions=alert.actions,
    #                        last_updated_time=alert.last_updated_time,
    #                        provisioning_state=alert.provisioning_state,
    #                    )
    #                )
    #        except Exception as error:
    #            logger.error(
    #                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
    #            )
    #    return activity_log_alerts


# @dataclass
# class ActivityLog:
#    id: str
#    resource_group: str
#    resource_id: str
#    operation_name: str
#    status: str
#    event_timestamp: str
#    caller: str
#    correlation_id: str
#    category: str
#    level: str
#    event_data_id: str
#    sub_status: str


@dataclass
class DiagnosticSetting:
    id: str
    name: str
    type: str
    event_hub_authorization_rule_id: str
    event_hub_name: str
    metrics: list
    logs: list
    workspace_id: str
    storage_account_id: str
    service_bus_rule_id: str
    marketplace_partner_id: str
    log_analytics_destination_type: str


# @dataclass
# class ActivityLogAlert:
#    id: str
#    name: str
#    description: str
#    enabled: bool
#    scopes: list
#    condition: dict
#    actions: list
#    last_updated_time: str
#    provisioning_state: str
