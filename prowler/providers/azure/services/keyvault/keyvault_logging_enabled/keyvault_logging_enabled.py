from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_logging_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_id, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                report = Check_Report_Azure(metadata=self.metadata(), resource=keyvault)
                report.subscription = subscription_id
                report.status = "FAIL"
                report.status_extended = f"Key Vault {keyvault.name} in subscription {subscription_id} does not have a diagnostic setting with audit logging."
                for diagnostic_setting in keyvault.monitor_diagnostic_settings or []:
                    has_audit = False
                    has_all_logs = False
                    for log in diagnostic_setting.logs:
                        if log.category_group == "audit" and log.enabled:
                            has_audit = True
                        if log.category_group == "allLogs" and log.enabled:
                            has_all_logs = True
                    if has_audit and has_all_logs:
                        report.status = "PASS"
                        report.status_extended = f"Key Vault {keyvault.name} in subscription {subscription_id} has a diagnostic setting with audit logging."
                        break
                findings.append(report)

        return findings
