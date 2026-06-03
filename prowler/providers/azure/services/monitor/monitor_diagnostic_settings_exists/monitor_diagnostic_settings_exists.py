from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_diagnostic_settings_exists(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_id in monitor_client.subscriptions:
            subscription_name = monitor_client.subscriptions[subscription_id]
            if monitor_client.resource_groups:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status = "MANUAL"
                report.status_extended = f"Subscription '{subscription_name}' ({subscription_id}): diagnostic-setting checks are subscription-scoped and cannot be accurately evaluated with resource group filtering enabled. Re-run without --azure-resource-group to get accurate results."
                findings.append(report)
                continue

            diagnostic_settings = monitor_client.diagnostics_settings.get(
                subscription_id, []
            )

            if diagnostic_settings:
                diagnostic_setting = diagnostic_settings[0]
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=diagnostic_setting
                )
                report.subscription = subscription_id
                report.status = "PASS"
                report.status_extended = f"Diagnostic setting {diagnostic_setting.name} found in subscription {subscription_name} ({subscription_id})."
            else:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status = "FAIL"
                report.status_extended = f"No diagnostic settings found in subscription {subscription_name} ({subscription_id})."

            findings.append(report)

        return findings
