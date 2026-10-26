from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.lib.runtime.runtime_version import (
    parse_java_version,
    runtime_version_at_least,
)
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_java_version_is_latest(Check):
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
                # The SDK can return None for linuxFxVersion, which getattr preserves
                linux_framework = (
                    getattr(app.configurations, "linux_fx_version", "") or ""
                )
                windows_version = getattr(app.configurations, "java_version", None)

                if "java" not in linux_framework.lower() and not windows_version:
                    continue

                framework = (
                    linux_framework
                    if "java" in linux_framework.lower()
                    else f"java{windows_version}"
                )
                minimum = app_client.audit_config.get("java_latest_version") or "17"

                report = Check_Report_Azure(metadata=self.metadata(), resource=app)
                report.subscription = subscription_id
                report.status = "FAIL"
                report.status_extended = f"Java version is set to '{framework}', which is below the minimum supported version 'java {minimum}', for app '{app.name}' in subscription '{subscription_name} ({subscription_id})'."

                if runtime_version_at_least(
                    parse_java_version(framework), parse_java_version(minimum)
                ):
                    report.status = "PASS"
                    report.status_extended = f"Java version is set to '{framework}', which meets the minimum supported version 'java {minimum}', for app '{app.name}' in subscription '{subscription_name} ({subscription_id})'."

                findings.append(report)

        return findings
