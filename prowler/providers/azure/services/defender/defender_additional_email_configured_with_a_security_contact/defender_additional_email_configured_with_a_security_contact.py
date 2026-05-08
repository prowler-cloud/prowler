from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_additional_email_configured_with_a_security_contact(Check):
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
            subscription_id,
            security_contact_configurations,
        ) in defender_client.security_contact_configurations.items():
            subscription_name = defender_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for contact_configuration in security_contact_configurations.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=contact_configuration
                )
                report.resource_name = (
                    contact_configuration.name
                    if contact_configuration.name
                    else "Security Contact"
                )
                report.subscription = subscription_id

                if len(contact_configuration.emails) > 0:
                    report.status = "PASS"
                    report.status_extended = f"There is another correct email configured for subscription {subscription_name} ({subscription_id})."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"There is not another correct email configured for subscription {subscription_name} ({subscription_id})."

                findings.append(report)

        return findings
