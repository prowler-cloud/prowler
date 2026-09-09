from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client


class backup_vaults_lock_enabled(Check):
    """Verify that every AWS Backup vault has Vault Lock enabled.

    A vault PASSES when ``Locked`` is set. ``ListBackupVaults`` reports the same
    flag for governance and compliance mode, so the mode itself is not asserted.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the AWS Backup Vault Lock check.

        Returns:
            A list of reports with each backup vault Vault Lock status.
        """
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
