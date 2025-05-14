from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.lib.monitor_alerts import check_alert_rule
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_alert_create_update_sqlserver_fr(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            activity_log_alerts,
        ) in monitor_client.alert_rules.items():
            for alert_rule in activity_log_alerts:
                if check_alert_rule(
                    alert_rule, "Microsoft.Sql/servers/firewallRules/write"
                ):
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=alert_rule
                    )
                    report.subscription = subscription_name
                    report.status = "PASS"
                    report.status_extended = f"There is an alert configured for creating/updating SQL Server firewall rule in subscription {subscription_name}."
                    break
            else:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_name
                report.resource_name = "Monitor"
                report.resource_id = "Monitor"
                report.status = "FAIL"
                report.status_extended = f"There is not an alert for creating/updating SQL Server firewall rule in subscription {subscription_name}."

            findings.append(report)

        return findings
