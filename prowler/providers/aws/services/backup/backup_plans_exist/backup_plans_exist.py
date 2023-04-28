from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client


class backup_plans_exist(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = "No Backup Plan Exist"
        report.resource_arn = ""
        report.resource_id = "No Backups"
        report.region = backup_client.region
        if backup_client.backup_plans:
            report.status = "PASS"
            report.status_extended = f"At least one backup plan exists: {backup_client.backup_plans[0].name}"
            report.resource_arn = backup_client.backup_plans[0].arn
            report.resource_id = backup_client.backup_plans[0].name
            report.region = backup_client.backup_plans[0].region

        findings.append(report)
        return findings
