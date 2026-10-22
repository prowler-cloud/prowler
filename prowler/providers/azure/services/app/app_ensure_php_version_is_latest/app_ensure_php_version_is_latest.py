from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.lib.runtime.runtime_version import (
    parse_runtime_version,
    runtime_version_at_least,
)
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_php_version_is_latest(Check):
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
                windows_version = getattr(app.configurations, "php_version", "")

                if "php" not in linux_framework.lower() and not windows_version:
                    continue

                framework = (
                    linux_framework
                    if "php" in linux_framework.lower()
                    else windows_version
                )
                minimum = app_client.audit_config.get("php_latest_version") or "8.5"

                report = Check_Report_Azure(metadata=self.metadata(), resource=app)
                report.subscription = subscription_id
                report.status = "FAIL"
                report.status_extended = f"PHP version is set to '{framework}', which is below the minimum supported version '{minimum}', for app '{app.name}' in subscription '{subscription_name} ({subscription_id})'."

                if runtime_version_at_least(
                    parse_runtime_version(framework), parse_runtime_version(minimum)
                ):
                    report.status = "PASS"
                    report.status_extended = f"PHP version is set to '{framework}', which meets the minimum supported version '{minimum}', for app '{app.name}' in subscription '{subscription_name} ({subscription_id})'."

                findings.append(report)

        return findings
