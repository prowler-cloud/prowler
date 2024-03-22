from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_using_http20(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            apps,
        ) in app_client.apps.items():
            for app_name, app in apps.items():
                report = Check_Report_Azure(self.metadata())
                report.status = "FAIL"
                report.subscription = subscription_name
                report.resource_name = app_name
                report.resource_id = app.resource_id
                report.location = app.location
                report.status_extended = f"HTTP/2.0 is not enabled for app '{app_name}' in subscription '{subscription_name}'."

                if app.configurations and getattr(
                    app.configurations, "http20_enabled", False
                ):
                    report.status = "PASS"
                    report.status_extended = f"HTTP/2.0 is enabled for app '{app_name}' in subscription '{subscription_name}'."

                findings.append(report)

        return findings
