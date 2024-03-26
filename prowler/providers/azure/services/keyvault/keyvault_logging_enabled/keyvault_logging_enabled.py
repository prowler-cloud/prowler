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
                    report.resource_name = keyvault.name
                    report.resource_id = keyvault.id
                    report.location = keyvault.location
                    report.status_extended = f"There are no diagnostic settings capturing audit logs for Key Vault {keyvault_name} in subscription {subscription_name}."
                    findings.append(report)
                else:
                    for diagnostic_setting in keyvault.monitor_diagnostic_settings:
                        report = Check_Report_Azure(self.metadata())
                        report.subscription = subscription_name
                        report.resource_name = diagnostic_setting.name
                        report.resource_id = diagnostic_setting.id
                        report.location = keyvault.location
                        report.status = "FAIL"
                        report.status_extended = f"Diagnostic setting {diagnostic_setting.name} for Key Vault {keyvault_name} in subscription {subscription_name} does not have audit logging."
                        audit = False
                        allLogs = False
                        for log in diagnostic_setting.logs:
                            if log.category_group == "audit" and log.enabled:
                                audit = True
                            if log.category_group == "allLogs" and log.enabled:
                                allLogs = True
                            if audit and allLogs:
                                report.status = "PASS"
                                report.status_extended = f"Diagnostic setting {diagnostic_setting.name} for Key Vault {keyvault_name} in subscription {subscription_name} has audit logging."
                                break

                    findings.append(report)

        return findings
