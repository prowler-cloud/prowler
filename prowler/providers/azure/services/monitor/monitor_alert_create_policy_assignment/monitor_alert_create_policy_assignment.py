from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.lib.monitor_alerts import check_alert_rule
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_alert_create_policy_assignment(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            activity_log_alerts,
        ) in monitor_client.alert_rules.items():
            if monitor_client.resource_groups:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_name
                report.resource_name = subscription_name
                report.resource_id = (
                    f"/subscriptions/{monitor_client.subscriptions[subscription_name]}"
                )
                report.status = "MANUAL"
                report.status_extended = f"Subscription '{subscription_name}': alert-rule checks are subscription-scoped and cannot be accurately evaluated with resource group filtering enabled. Re-run without --azure-resource-group to get accurate results."
                findings.append(report)
                continue
            for alert_rule in activity_log_alerts:
                if check_alert_rule(
                    alert_rule, "Microsoft.Authorization/policyAssignments/write"
                ):
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=alert_rule
                    )
                    report.subscription = subscription_name
                    report.status = "PASS"
                    report.status_extended = f"There is an alert configured for creating Policy Assignments in subscription {subscription_name}."
                    break
            else:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_name
                report.resource_name = subscription_name
                report.resource_id = (
                    f"/subscriptions/{monitor_client.subscriptions[subscription_name]}"
                )
                report.status = "FAIL"
                report.status_extended = f"There is not an alert for creating Policy Assignments in subscription {subscription_name}."

            findings.append(report)

        return findings
