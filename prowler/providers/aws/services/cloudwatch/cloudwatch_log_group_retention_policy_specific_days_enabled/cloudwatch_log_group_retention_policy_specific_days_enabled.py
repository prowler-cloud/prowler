from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_group_retention_policy_specific_days_enabled(Check):
    def execute(self):
        findings = []

        # log_group_retention_days, default: 365 days
        specific_retention_days = logs_client.audit_config.get(
            "log_group_retention_days", 365
        )
        if logs_client.log_groups:
            for log_group in logs_client.log_groups:
                report = Check_Report_AWS(self.metadata())
                report.region = log_group.region
                report.resource_id = log_group.name
                report.resource_arn = log_group.arn
                report.resource_tags = log_group.tags
                if (
                    log_group.never_expire is False
                    and log_group.retention_days < specific_retention_days
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Log Group {log_group.name} has less than {specific_retention_days} days retention period ({log_group.retention_days} days)."
                else:
                    report.status = "PASS"
                    if log_group.never_expire is True:
                        report.status_extended = f"Log Group {log_group.name} comply with {specific_retention_days} days retention period since it never expires."
                    else:
                        report.status_extended = f"Log Group {log_group.name} comply with {specific_retention_days} days retention period since it has {log_group.retention_days} days."
                findings.append(report)
        return findings
