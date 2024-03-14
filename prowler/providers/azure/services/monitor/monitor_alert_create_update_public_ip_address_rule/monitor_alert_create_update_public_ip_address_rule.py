from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.lib.monitor_alerts import check_alert_rule
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_alert_create_update_public_ip_address_rule(Check):
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
            report.status_extended = f"There is not an alert for creating/updating Public IP address rule in subscription {subscription_name}."
            for alert_rule in activity_log_alerts:
                if check_alert_rule(
                    alert_rule, "Microsoft.Network/publicIPAddresses/write"
                ):
                    report.status = "PASS"
                    report.resource_name = alert_rule.name
                    report.resource_id = alert_rule.id
                    report.subscription = subscription_name
                    report.status_extended = f"There is an alert configured for creating/updating Public IP address rule in subscription {subscription_name}."
                    break

            findings.append(report)

        return findings
