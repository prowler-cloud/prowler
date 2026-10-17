from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_logging_enabled(Check):
    """Ensure every Key Vault sends audit logs through a diagnostic setting."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate the diagnostic settings of every Key Vault.

        Returns:
            One finding per Key Vault: PASS when an enabled diagnostic setting
            log collects AuditEvent, either through the AuditEvent category or
            through the audit or allLogs category group (both include
            AuditEvent), FAIL otherwise.
        """
        findings = []

        for subscription_id, key_vaults in keyvault_client.key_vaults.items():
            subscription_name = keyvault_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for keyvault in key_vaults:
                report = Check_Report_Azure(metadata=self.metadata(), resource=keyvault)
                report.subscription = subscription_id
                report.status = "FAIL"
                report.status_extended = f"Key Vault {keyvault.name} in subscription {subscription_name} ({subscription_id}) does not have a diagnostic setting with audit logging."
                for diagnostic_setting in keyvault.monitor_diagnostic_settings or []:
                    has_audit_category = False
                    has_audit_group = False
                    has_all_logs = False
                    for log in diagnostic_setting.logs:
                        if log.category == "AuditEvent" and log.enabled:
                            has_audit_category = True
                        if log.category_group == "audit" and log.enabled:
                            has_audit_group = True
                        if log.category_group == "allLogs" and log.enabled:
                            has_all_logs = True
                    if has_audit_category or has_audit_group or has_all_logs:
                        report.status = "PASS"
                        report.status_extended = f"Key Vault {keyvault.name} in subscription {subscription_name} ({subscription_id}) has a diagnostic setting with audit logging."
                        break
                findings.append(report)

        return findings
