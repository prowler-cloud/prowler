from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_notify_emails_to_owners(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            security_contact_configurations,
        ) in defender_client.security_contact_configurations.items():
            for contact_configuration in security_contact_configurations.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource=contact_configuration,
                )
                report.resource_name = (
                    contact_configuration.name
                    if contact_configuration.name
                    else "Security Contact"
                )
                report.subscription = subscription_name
                if (
                    contact_configuration.notifications_by_role.state
                    and "Owner" in contact_configuration.notifications_by_role.roles
                ):
                    report.status = "PASS"
                    report.status_extended = f"The Owner role is notified for subscription {subscription_name}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"The Owner role is not notified for subscription {subscription_name}."

                findings.append(report)

        return findings
