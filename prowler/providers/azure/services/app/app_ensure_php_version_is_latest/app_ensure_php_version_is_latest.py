from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_php_version_is_latest(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            apps,
        ) in app_client.apps.items():
            for app_name, app in apps.items():
                framework = getattr(app.configurations, "linux_fx_version", "")

                if "php" in framework.lower():
                    report = Check_Report_Azure(self.metadata())
                    report.status = "PASS"
                    report.subscription = subscription_name
                    report.resource_name = app_name
                    report.resource_id = app.resource_id
                    php_latest_version = app_client.audit_config.get(
                        "php_latest_version", "8.2"
                    )
                    report.status_extended = f"PHP version is set to {php_latest_version} for app '{app_name}' in subscription '{subscription_name}'."

                    if php_latest_version not in framework:
                        report.status = "FAIL"
                        report.status_extended = f"PHP version is not set to {php_latest_version} for app '{app_name}' in subscription '{subscription_name}'."

                    findings.append(report)

        return findings
