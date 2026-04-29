from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_register_with_identity(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_id,
            apps,
        ) in app_client.apps.items():
            subscription_name = app_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for app in apps.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=app)
                report.subscription = subscription_id
                report.status = "PASS"
                report.status_extended = f"App '{app.name}' in subscription '{subscription_name} ({subscription_id})' has an identity configured."

                if not app.identity:
                    report.status = "FAIL"
                    report.status_extended = f"App '{app.name}' in subscription '{subscription_name} ({subscription_id})' does not have an identity configured."

                findings.append(report)

        return findings
