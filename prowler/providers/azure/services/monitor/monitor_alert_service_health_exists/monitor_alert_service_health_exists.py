from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_alert_service_health_exists(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription_id in monitor_client.subscriptions:
            subscription_name = monitor_client.subscriptions[subscription_id]
            if monitor_client.resource_groups:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status = "MANUAL"
                report.status_extended = f"Subscription '{subscription_name}' ({subscription_id}): alert-rule checks are subscription-scoped and cannot be accurately evaluated with resource group filtering enabled. Re-run without --azure-resource-group to get accurate results."
            else:
                for alert_rule in monitor_client.alert_rules.get(subscription_id, []):
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
                            report.subscription = subscription_id
                            report.status = "PASS"
                            report.status_extended = f"There is an activity log alert for Service Health in subscription {subscription_name} ({subscription_id})."
                            break
                else:
                    report = Check_Report_Azure(metadata=self.metadata(), resource={})
                    report.subscription = subscription_id
                    report.resource_name = subscription_id
                    report.resource_id = f"/subscriptions/{subscription_id}"
                    report.status = "FAIL"
                    report.status_extended = f"There is no activity log alert for Service Health in subscription {subscription_name} ({subscription_id})."

            findings.append(report)

        return findings
