from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_auth_is_set_up(Check):
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
                report.status_extended = f"Authentication is set up for app '{app.name}' in subscription '{subscription_name}'."

                if not app.auth_enabled:
                    report.status = "FAIL"
                    report.status_extended = f"Authentication is not set up for app '{app.name}' in subscription '{subscription_name}'."

                findings.append(report)

        return findings
