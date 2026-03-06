from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_alert_service_health_exists(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for (
            subscription_name,
            activity_log_alerts,
        ) in monitor_client.alert_rules.items():
            for alert_rule in activity_log_alerts:
                # Check if alert rule is enabled and has required Service Health conditions
                if alert_rule.enabled:
                    has_service_health_category = False
                    has_incident_type_incident = False
                    for element in alert_rule.condition.all_of:
                        if (
                            element.field == "category"
                            and element.equals == "ServiceHealth"
                        ):
                            has_service_health_category = True
                        if (
                            element.field == "properties.incidentType"
                            and element.equals == "Incident"
                        ):
                            has_incident_type_incident = True

                    if has_service_health_category and has_incident_type_incident:
                        report = Check_Report_Azure(
                            metadata=self.metadata(), resource=alert_rule
                        )
                        report.subscription = subscription_name
                        report.status = "PASS"
                        report.status_extended = f"There is an activity log alert for Service Health in subscription {subscription_name}."
                        break
            else:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_name
                report.resource_name = subscription_name
                report.resource_id = (
                    f"/subscriptions/{monitor_client.subscriptions[subscription_name]}"
                )
                report.status = "FAIL"
                report.status_extended = f"There is no activity log alert for Service Health in subscription {subscription_name}."

            findings.append(report)

        return findings
