from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_ensure_diagnostic_setting_appropiate(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            diagnostic_settings,
        ) in monitor_client.diagnostics_settings.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = subscription_name
            report.resource_name = "Monitor"
            report.resource_id = "Monitor"
            report.status_extended = f"There are no diagnostic settings capturing appropiate categories in subscription {subscription_name}."
            for diagnostic_setting in diagnostic_settings:
                if (
                    diagnostic_setting.logs[0].enabled
                    and diagnostic_setting.logs[1].enabled
                    and diagnostic_setting.logs[3].enabled
                    and diagnostic_setting.logs[5].enabled
                ):
                    report.status = "PASS"
                    report.status_extended = f"There is at least one diagnostic setting capturing appropiate categories in subscription {subscription_name}."
                    break

            findings.append(report)

        return findings
