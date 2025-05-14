from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_client_certificates_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            apps,
        ) in app_client.apps.items():
            for app in apps.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=app)
                report.subscription = subscription_name
                report.status = "PASS"
                report.status_extended = f"Clients are required to present a certificate for app '{app.name}' in subscription '{subscription_name}'."

                if app.client_cert_mode != "Required":
                    report.status = "FAIL"
                    report.status_extended = f"Clients are not required to present a certificate for app '{app.name}' in subscription '{subscription_name}'."

                findings.append(report)

        return findings
