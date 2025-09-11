from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_additional_email_configured_with_a_security_contact(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

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

                if len(contact_configuration.emails) > 0:
                    report.status = "PASS"
                    report.status_extended = f"There is another correct email configured for subscription {subscription_name}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"There is not another correct email configured for subscription {subscription_name}."

                findings.append(report)

        return findings
