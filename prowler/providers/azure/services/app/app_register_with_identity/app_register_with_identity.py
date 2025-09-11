from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_register_with_identity(Check):
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
                report.status_extended = f"App '{app.name}' in subscription '{subscription_name}' has an identity configured."

                if not app.identity:
                    report.status = "FAIL"
                    report.status_extended = f"App '{app.name}' in subscription '{subscription_name}' does not have an identity configured."

                findings.append(report)

        return findings
