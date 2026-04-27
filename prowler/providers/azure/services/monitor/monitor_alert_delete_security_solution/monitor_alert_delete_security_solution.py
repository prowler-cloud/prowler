from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.lib.monitor_alerts import check_alert_rule
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_alert_delete_security_solution(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_id,
            activity_log_alerts,
        ) in monitor_client.alert_rules.items():
            for alert_rule in activity_log_alerts:
                if check_alert_rule(
                    alert_rule, "Microsoft.Security/securitySolutions/delete"
                ):
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=alert_rule
                    )
                    report.subscription = subscription_id
                    report.status = "PASS"
                    report.status_extended = f"There is an alert configured for deleting Security Solution in subscription {subscription_id}."
                    break
            else:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = (
                    f"/subscriptions/{subscription_id}"
                )
                report.status = "FAIL"
                report.status_extended = f"There is not an alert for deleting Security Solution in subscription {subscription_id}."

            findings.append(report)

        return findings
