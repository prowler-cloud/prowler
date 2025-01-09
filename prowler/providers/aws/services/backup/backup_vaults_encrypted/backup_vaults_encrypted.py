from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client


class backup_vaults_encrypted(Check):
    def execute(self):
        findings = []
        if backup_client.backup_vaults:
            for backup_vault in backup_client.backup_vaults:
                report = Check_Report_AWS(self.metadata())
                report.resource_arn = backup_vault.arn
                report.resource_id = backup_vault.name
                report.region = backup_vault.region
                report.resource_tags = backup_vault.tags
                report.status = "FAIL"
                report.status_extended = (
                    f"Backup Vault {backup_vault.name} is not encrypted at rest."
                )
                if backup_vault.encryption:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Backup Vault {backup_vault.name} is encrypted at rest."
                    )
                findings.append(report)

        return findings
