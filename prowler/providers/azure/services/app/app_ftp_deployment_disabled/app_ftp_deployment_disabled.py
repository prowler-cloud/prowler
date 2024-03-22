from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ftp_deployment_disabled(Check):
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
                report.status_extended = f"FTP is enabled for app '{app_name}' in subscription '{subscription_name}'."

                if (
                    app.configurations
                    and getattr(app.configurations, "ftps_state", "AllAllowed")
                    != "AllAllowed"
                ):
                    report.status = "PASS"
                    report.status_extended = f"FTP is disabled for app '{app_name}' in subscription '{subscription_name}'."

                findings.append(report)

        return findings
