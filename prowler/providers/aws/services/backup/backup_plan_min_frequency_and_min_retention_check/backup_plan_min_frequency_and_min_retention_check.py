from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client


class backup_plan_min_frequency_and_min_retention_check(Check):
    def execute(self):
        findings = []

        # Define the required minimum frequency and retention period
        min_frequency = "cron(0 5 ? * * *)"  # set minimum frequency here (5:00am)
        min_retention_days = 30  # minimum retention period in days

        for backup_plan in backup_client.backup_plans:
            report = Check_Report_AWS(self.metadata())
            report.region = backup_plan.region
            report.resource_arn = backup_plan.arn
            report.resource_id = backup_plan.id
            report.resource_tags = getattr(backup_plan, 'tags', [])

            meets_requirements = False

            if hasattr(backup_plan, 'advanced_settings'):
                for rule in backup_plan.advanced_settings:
                    schedule_expression = rule.get('ScheduleExpression')
                    retention_days = rule.get('Lifecycle', {}).get('DeleteAfterDays')

                    if schedule_expression == min_frequency and retention_days >= min_retention_days:
                        meets_requirements = True
                        break

            if meets_requirements:
                report.status = "PASS"
                report.status_extended = f"Backup plan '{backup_plan.name}' meets the minimum frequency and retention period."
            else:
                report.status = "FAIL"
                report.status_extended = f"Backup plan '{backup_plan.name}' does not meet the minimum frequency and retention period."

            findings.append(report)

        return findings
