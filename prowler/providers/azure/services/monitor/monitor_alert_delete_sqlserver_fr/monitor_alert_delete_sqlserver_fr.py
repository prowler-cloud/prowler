from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.lib.monitoring_alerts_review.monitoring_alerts_review import (
    check_alerts_review,
)
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_alert_delete_sqlserver_fr(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            activity_log_alerts,
        ) in monitor_client.alert_rules.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = subscription_name
            report.resource_name = "Monitor"
            report.resource_id = "Monitor"
            report.status_extended = f"There is not an alert for deleting SQL Server firewall rule in subscription {subscription_name}."
            for alert_rule in activity_log_alerts:
                check = check_alerts_review(
                    alert_rule, "Microsoft.Sql/servers/firewallRules/delete"
                )
                if check:
                    report.status = "PASS"
                    report.resource_name = alert_rule.name
                    report.resource_id = alert_rule.id
                    report.subscription = subscription_name
                    report.status_extended = f"There is an alert configured for deleting SQL Server firewall rule in subscription {subscription_name}."
                    break

            findings.append(report)
        return findings
