from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_notify_emails_to_owners(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            security_contacts,
        ) in defender_client.security_contacts.items():
            for contact in security_contacts.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource_metadata=contact
                )
                report.subscription = subscription_name
                report.status = "PASS"
                report.status_extended = (
                    f"The Owner role is notified for subscription {subscription_name}."
                )
                if (
                    contact.notified_roles_state != "On"
                    or "Owner" not in contact.notified_roles
                ):
                    report.status = "FAIL"
                    report.status_extended = f"The Owner role is not notified for subscription {subscription_name}."

                findings.append(report)

        return findings
