from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client


class backup_vaults_exist(Check):
    def execute(self):
        findings = []

        for backup_vault in backup_client.backup_vaults:
            report = Check_Report_AWS(self.metadata())
            report.status = "PASS"
            report.status_extended = f"Backup Vaults Exist: {backup_vault.name}"
            report.resource_arn = backup_vault.arn
            report.resource_id = backup_vault.name
            report.region = backup_vault.region
            findings.append(report)

        if not findings:
            report = Check_Report_AWS(self.metadata())
            report.status = "FAIL"
            report.status_extended = "No Backup Vaults Exist"
            report.resource_arn = "AWS Backup"
            report.resource_id = "AWS Backup"
            report.region = "Global"
            findings.append(report)

        return findings
