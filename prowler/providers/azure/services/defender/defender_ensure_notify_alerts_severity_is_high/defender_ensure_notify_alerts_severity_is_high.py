from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_notify_alerts_severity_is_high(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        if defender_client.resource_groups:
            for subscription in defender_client.subscriptions:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription
                report.resource_name = "Not Applicable"
                report.resource_id = "Not Applicable"
                report.status = "MANUAL"
                report.status_extended = f"Subscription '{subscription}': this check is subscription-scoped and cannot be evaluated when --azure-resource-group is active. Re-run without --azure-resource-group to get full results."
                findings.append(report)
            return findings

        for (
            subscription_name,
            security_contact_configurations,
        ) in defender_client.security_contact_configurations.items():
            for contact_configuration in security_contact_configurations.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=contact_configuration
                )
                report.resource_name = (
                    contact_configuration.name
                    if contact_configuration.name
                    else "Security Contact"
                )
                report.subscription = subscription_name
                report.status = "FAIL"
                report.status_extended = f"Notifications are not enabled for alerts with a minimum severity of high or lower in subscription {subscription_name}."

                if (
                    contact_configuration.alert_minimal_severity
                    and contact_configuration.alert_minimal_severity != "Critical"
                ):
                    report.status = "PASS"
                    report.status_extended = f"Notifications are enabled for alerts with a minimum severity of high or lower ({contact_configuration.alert_minimal_severity}) in subscription {subscription_name}."

                findings.append(report)

        return findings
