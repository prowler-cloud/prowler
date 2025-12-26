from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_logstore_retention_period(Check):
    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        # Get configurable max days from audit config (default: 365 days)
        min_log_retention_days = sls_client.audit_config.get(
            "min_log_retention_days", 365
        )

        for log_store in sls_client.log_stores:
            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=log_store
            )
            report.resource_id = log_store.name
            report.resource_arn = log_store.arn
            report.region = log_store.region

            # Check retention
            if log_store.retention_days >= min_log_retention_days:
                report.status = "PASS"
                report.status_extended = f"SLS LogStore {log_store.name} in project {log_store.project} has retention set to {log_store.retention_days} days (>= {min_log_retention_days} days)."
            else:
                report.status = "FAIL"
                report.status_extended = f"SLS LogStore {log_store.name} in project {log_store.project} has retention set to {log_store.retention_days} days (less than {min_log_retention_days} days)."

            findings.append(report)

        return findings
