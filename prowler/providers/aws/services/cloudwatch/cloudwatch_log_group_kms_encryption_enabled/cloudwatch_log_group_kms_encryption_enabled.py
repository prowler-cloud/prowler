from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.check.resource_limit import get_resource_scan_limit, limited_findings
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_group_kms_encryption_enabled(Check):
    def execute(self):
        def evaluate(log_group):
            report = Check_Report_AWS(metadata=self.metadata(), resource=log_group)
            if log_group.kms_id:
                report.status = "PASS"
                report.status_extended = f"Log Group {log_group.name} does have AWS KMS key {log_group.kms_id} associated."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Log Group {log_group.name} does not have AWS KMS keys associated."
                )
            return report

        return limited_findings(
            logs_client.iter_log_groups(),
            evaluate,
            get_resource_scan_limit(
                logs_client.audit_config, "max_cloudwatch_log_groups"
            ),
        )
