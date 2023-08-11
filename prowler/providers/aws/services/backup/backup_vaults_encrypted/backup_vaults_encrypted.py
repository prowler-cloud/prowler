from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client


class backup_vaults_encrypted(Check):
    def execute(self):
        findings = []

        for backup_vault in backup_client.backup_vaults:
            # By default we assume that the result is fail
            report = Check_Report_AWS(self.metadata())
            report.status = "FAIL"
            report.status_extended = (
                f"Backup Vault {backup_vault.name} is not encrypted."
            )
            report.resource_arn = backup_vault.arn
            report.resource_id = backup_vault.name
            report.region = backup_vault.region
            # if it is encrypted we only change the status and the status extended
            if backup_vault.encryption:
                report.status = "PASS"
                report.status_extended = (
                    f"Backup Vault {backup_vault.name} is encrypted."
                )
            # then we store the finding
            findings.append(report)

        return findings
