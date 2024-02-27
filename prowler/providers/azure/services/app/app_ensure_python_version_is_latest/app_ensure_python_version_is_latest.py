from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_python_version_is_latest(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            apps,
        ) in app_client.apps.items():
            for app_name, app in apps.items():
                framework = getattr(app.configurations, "linux_fx_version", "")

                if (
                    "python" in framework.lower()
                    or getattr(app.configurations, "python_version", None) != ""
                ):
                    report = Check_Report_Azure(self.metadata())
                    report.status = "FAIL"
                    report.subscription = subscription_name
                    report.resource_name = app_name
                    report.resource_id = app.resource_id
                    python_latest_version = app_client.audit_config.get(
                        "python_latest_version", "3.12"
                    )
                    report.status_extended = f"Python version is '{framework}', the latest version that you could use is the '{python_latest_version}' version, for app '{app_name}' in subscription '{subscription_name}'."

                    if (
                        python_latest_version in framework
                        or getattr(app.configurations, "python_version", None)
                        == python_latest_version
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Python version is set to '{python_latest_version}' for app '{app_name}' in subscription '{subscription_name}'."

                    findings.append(report)

        return findings
