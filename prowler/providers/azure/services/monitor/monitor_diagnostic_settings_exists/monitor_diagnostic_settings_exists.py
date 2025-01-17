from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_diagnostic_settings_exists(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            diagnostic_settings,
        ) in monitor_client.diagnostics_settings.items():
            report = Check_Report_Azure(
                metadata=self.metadata(), resource_metadata=diagnostic_settings
            )
            report.subscription = subscription_name
            report.resource_name = "Diagnostic Settings"
            report.resource_id = "diagnostic_settings"
            report.status = "FAIL"
            report.status_extended = (
                f"No diagnostic settings found in subscription {subscription_name}."
            )
            if diagnostic_settings:
                report.status = "PASS"
                report.status_extended = (
                    f"Diagnostic settings found in subscription {subscription_name}."
                )

            findings.append(report)

        return findings
