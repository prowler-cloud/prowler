from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.check.resource_limit import get_resource_scan_limit, limited_findings
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_group_retention_policy_specific_days_enabled(Check):
    def execute(self):
        # log_group_retention_days, default: 365 days
        specific_retention_days = logs_client.audit_config.get(
            "log_group_retention_days", 365
        )

        def evaluate(log_group):
            report = Check_Report_AWS(metadata=self.metadata(), resource=log_group)
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
            return report

        return limited_findings(
            logs_client.iter_log_groups(),
            evaluate,
            get_resource_scan_limit(
                logs_client.audit_config, "max_cloudwatch_log_groups"
            ),
        )
