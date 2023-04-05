from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client


class backup_reportplans_exist(Check):
    def execute(self):
        findings = []

        for backup_report_plan in backup_client.backup_report_plans:
            report = Check_Report_AWS(self.metadata())
            report.status = "PASS"
            report.status_extended = (
                f"Backup Report Plan Exist: {backup_report_plan.name}"
            )
            report.resource_arn = backup_report_plan.arn
            report.resource_id = backup_report_plan.name
            report.region = backup_report_plan.region
            findings.append(report)

        if not findings:
            report = Check_Report_AWS(self.metadata())
            report.status = "FAIL"
            report.status_extended = "No Backup Report Plan Exist"
            report.resource_arn = "AWS Backup"
            report.resource_id = "AWS Backup"
            report.region = "Global"
            findings.append(report)

        return findings
