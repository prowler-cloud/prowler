from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_sql_audit_retention(Check):
    """Check if 'Auditing' Retention is greater than the configured period."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        # Get configurable max days from audit config (default: 180 days - 6 months)
        min_audit_retention_days = rds_client.audit_config.get(
            "min_rds_audit_retention_days", 180
        )

        for instance in rds_client.instances:
            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=instance
            )
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"acs:rds:{instance.region}:{rds_client.audited_account}:dbinstance/{instance.id}"

            if (
                instance.audit_log_enabled
                and instance.audit_log_retention >= min_audit_retention_days
            ):
                report.status = "PASS"
                report.status_extended = f"RDS Instance {instance.name} has SQL audit enabled with retention of {instance.audit_log_retention} days (>= {min_audit_retention_days} days)."
            elif instance.audit_log_enabled:
                report.status = "FAIL"
                report.status_extended = f"RDS Instance {instance.name} has SQL audit enabled but retention is {instance.audit_log_retention} days (< {min_audit_retention_days} days)."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {instance.name} does not have SQL audit enabled."
                )

            findings.append(report)

        return findings
