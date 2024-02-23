from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_auth_is_set_up(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            apps,
        ) in app_client.apps.items():
            for app_name, app in apps.items():
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = app_name
                report.resource_id = app.resource_id
                report.status_extended = f"Authentication is set up for app '{app_name}' in subscription '{subscription_name}'."

                if not app.auth_enabled:
                    report.status = "FAIL"
                    report.status_extended = f"Authentication is not set up for app '{app_name}' in subscription '{subscription_name}'."

                findings.append(report)

        return findings
