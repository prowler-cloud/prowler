from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_java_version_is_latest(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            apps,
        ) in app_client.apps.items():
            for app in apps.values():
                linux_framework = getattr(app.configurations, "linux_fx_version", "")
                windows_framework_version = getattr(
                    app.configurations, "java_version", None
                )

                if "java" in linux_framework.lower() or windows_framework_version:
                    report = Check_Report_Azure(metadata=self.metadata(), resource=app)
                    report.subscription = subscription_name
                    report.status = "FAIL"
                    java_latest_version = app_client.audit_config.get(
                        "java_latest_version", "17"
                    )
                    report.status_extended = f"Java version is set to '{f'java{windows_framework_version}' if windows_framework_version else linux_framework}', but should be set to 'java {java_latest_version}' for app '{app.name}' in subscription '{subscription_name}'."

                    if (
                        f"java{java_latest_version}" in linux_framework
                        or java_latest_version == windows_framework_version
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Java version is set to 'java {java_latest_version}' for app '{app.name}' in subscription '{subscription_name}'."

                    findings.append(report)

        return findings
