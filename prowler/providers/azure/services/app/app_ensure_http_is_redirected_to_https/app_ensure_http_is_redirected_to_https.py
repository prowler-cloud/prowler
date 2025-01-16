from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_http_is_redirected_to_https(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            apps,
        ) in app_client.apps.items():
            for app in apps.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource_metadata=app
                )
                report.subscription = subscription_name
                report.status = "PASS"
                report.status_extended = f"HTTP is redirected to HTTPS for app '{app.name}' in subscription '{subscription_name}'."

                if not app.https_only:
                    report.status = "FAIL"
                    report.status_extended = f"HTTP is not redirected to HTTPS for app '{app.name}' in subscription '{subscription_name}'."

                findings.append(report)

        return findings
