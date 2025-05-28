from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_notify_alerts_severity_is_high(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            security_contacts,
        ) in defender_client.security_contacts.items():
            for contact in security_contacts.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=contact)
                report.subscription = subscription_name
                report.status = "FAIL"
                report.status_extended = f"Notifications are not enabled for alerts with a minimum severity of high or lower in subscription {subscription_name}."

                if (
                    contact.alert_notifications_minimal_severity != "Critical"
                    and contact.alert_notifications_minimal_severity != ""
                ):
                    report.status = "PASS"
                    report.status_extended = f"Notifications are enabled for alerts with a minimum severity of high or lower ({contact.alert_notifications_minimal_severity}) in subscription {subscription_name}."

                findings.append(report)

        return findings
