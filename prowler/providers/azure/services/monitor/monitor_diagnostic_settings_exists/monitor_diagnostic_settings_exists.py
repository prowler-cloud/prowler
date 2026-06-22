from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_diagnostic_settings_exists(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_id,
            diagnostic_settings,
        ) in monitor_client.diagnostics_settings.items():
            subscription_name = monitor_client.subscriptions.get(
                subscription_id, subscription_id
            )
            if diagnostic_settings:
                # At least one diagnostic setting exists - report on the first one
                diagnostic_setting = diagnostic_settings[0]
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=diagnostic_setting
                )
                report.subscription = subscription_id
                report.status = "PASS"
                report.status_extended = f"Diagnostic setting {diagnostic_setting.name} found in subscription {subscription_name} ({subscription_id})."
            else:
                # No diagnostic settings - report on subscription
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status = "FAIL"
                report.status_extended = f"No diagnostic settings found in subscription {subscription_name} ({subscription_id})."

            findings.append(report)

        return findings
