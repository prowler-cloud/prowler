from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client


class backup_vaults_exist(Check):
    def execute(self):
        findings = []
        if backup_client.backup_vaults is not None:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=backup_client.backup_vaults
            )
            report.resource_arn = backup_client.backup_vault_arn_template
            report.resource_id = backup_client.audited_account
            report.region = backup_client.region
            report.resource_tags = []
            report.status = "FAIL"
            report.status_extended = "No Backup Vault exist."
            if backup_client.backup_vaults:
                report = Check_Report_AWS(
                    metadata=self.metadata(),
                    resource=backup_client.backup_vaults[0],
                )
                report.status = "PASS"
                report.status_extended = f"At least one backup vault exists: {backup_client.backup_vaults[0].name}."
            findings.append(report)
        return findings
