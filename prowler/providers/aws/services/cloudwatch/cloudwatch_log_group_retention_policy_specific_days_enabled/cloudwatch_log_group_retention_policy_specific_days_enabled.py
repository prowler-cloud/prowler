from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_group_retention_policy_specific_days_enabled(Check):
    def execute(self):
        findings = []
        specific_retention_days = get_config_var("log_group_retention_days")
        for log_group in logs_client.log_groups:
            report = Check_Report_AWS(self.metadata())
            report.region = log_group.region
            report.resource_id = log_group.name
            report.resource_arn = log_group.arn
            if log_group.retention_days < specific_retention_days:
                report.status = "FAIL"
                report.status_extended = f"Log Group {log_group.name} has less than {specific_retention_days} days retention period ({log_group.retention_days} days)."
            else:
                report.status = "PASS"
                report.status_extended = f"Log Group {log_group.name} comply with {specific_retention_days} days retention period since it has {log_group.retention_days} days."
            findings.append(report)
        return findings
