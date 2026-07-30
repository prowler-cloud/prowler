from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client


class backup_vaults_lock_enabled(Check):
    def execute(self):
        findings = []
        if backup_client.backup_vaults:
            for backup_vault in backup_client.backup_vaults:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=backup_vault
                )
                report.status = "FAIL"
                report.status_extended = f"Backup Vault {backup_vault.name} does not have Vault Lock enabled."
                if backup_vault.locked:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Backup Vault {backup_vault.name} has Vault Lock enabled."
                    )
                findings.append(report)

        return findings
