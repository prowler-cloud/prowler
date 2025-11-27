from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_sql_audit_enabled(Check):
    """Check if 'Auditing' is set to 'On' for applicable database instances."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for instance in rds_client.instances:
            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=instance
            )
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"acs:rds:{instance.region}:{rds_client.audited_account}:dbinstance/{instance.id}"

            if instance.audit_log_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {instance.name} has SQL audit enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {instance.name} does not have SQL audit enabled."
                )

            findings.append(report)

        return findings
