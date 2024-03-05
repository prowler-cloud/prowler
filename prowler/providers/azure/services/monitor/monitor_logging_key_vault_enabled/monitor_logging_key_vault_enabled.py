from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_logging_key_vault_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            diagnostic_settings,
        ) in monitor_client.diagnostics_settings_for_key_vault.items():
            report = Check_Report_Azure(self.metadata())
            if not diagnostic_settings:
                report.status = "FAIL"
                report.subscription = subscription_name
                report.resource_name = "Monitor"
                report.resource_id = ""
                report.status_extended = f"There are no diagnostic settings capturing appropiate categories in subscription {subscription_name}."
                findings.append(report)

            for diagnostics_setting in diagnostic_settings:
                diagnostic_setting_name = diagnostics_setting.id.split("/")[-1]
                for log in diagnostics_setting.logs:
                    if log.category == "AuditEvent":
                        report = Check_Report_Azure(self.metadata())
                        if log.enabled:
                            report.status = "PASS"
                            report.status_extended = f"Diagnostic setting {diagnostic_setting_name} for Key Vault in subscription {subscription_name} is capturing AuditEvent category."
                            report.subscription = subscription_name
                            report.resource_name = (
                                diagnostics_setting.storage_account_name
                            )
                            report.diagnostic_setting_name = diagnostic_setting_name
                        else:
                            report.status = "FAIL"
                            report.status_extended = f"Diagnostic setting {diagnostic_setting_name} for Key Vault in subscription {subscription_name} is not capturing AuditEvent category."
                            report.subscription = subscription_name
                            report.resource_name = (
                                diagnostics_setting.storage_account_name
                            )
                            report.diagnostic_setting_name = diagnostic_setting_name

                        findings.append(report)

        return findings
