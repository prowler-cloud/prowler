from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_logging_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                keyvault_name = keyvault.name
                subscription_name = subscription
                if not keyvault.monitor_diagnostic_settings:
                    report = Check_Report_Azure(self.metadata())
                    report.status = "FAIL"
                    report.subscription = subscription_name
                    report.resource_name = "KeyVault"
                    report.resource_id = "KeyVault"
                    report.status_extended = f"There are no diagnostic settings capturing appropiate categories in Key Vault {keyvault_name} in subscription {subscription_name}."
                    findings.append(report)
                else:
                    for diagnostic_setting in keyvault.monitor_diagnostic_settings:
                        report = Check_Report_Azure(self.metadata())
                        report.subscription = subscription_name
                        report.resource_name = diagnostic_setting.name
                        report.resource_id = diagnostic_setting.id
                        for log in diagnostic_setting.logs:
                            if log.category == "AuditEvent" and log.enabled:
                                report.status = "PASS"
                                report.status_extended = f"Diagnostic setting {diagnostic_setting.name} for Key Vault {keyvault_name} in subscription {subscription_name} is capturing AuditEvent category."
                                break

                            else:
                                report.status = "FAIL"
                                report.status_extended = f"Diagnostic setting {diagnostic_setting.name} for Key Vault {keyvault_name} in subscription {subscription_name} is not capturing AuditEvent category."

                    findings.append(report)

        return findings
