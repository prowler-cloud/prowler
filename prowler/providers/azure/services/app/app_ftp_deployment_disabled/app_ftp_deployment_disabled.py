from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ftp_deployment_disabled(Check):
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
                report.status = "FAIL"
                report.status_extended = f"FTP is enabled for app '{app.name}' in subscription '{subscription_name}'."
                if (
                    app.configurations
                    and getattr(app.configurations, "ftps_state", "AllAllowed")
                    != "AllAllowed"
                ):
                    report.status = "PASS"
                    report.status_extended = f"FTP is disabled for app '{app.name}' in subscription '{subscription_name}'."

                findings.append(report)

        return findings
