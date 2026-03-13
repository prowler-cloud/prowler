from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_postgresql_log_disconnections_enabled(Check):
    """Check if parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for instance in rds_client.instances:
            if "PostgreSQL" in instance.engine:
                report = CheckReportAlibabaCloud(
                    metadata=self.metadata(), resource=instance
                )
                report.region = instance.region
                report.resource_id = instance.id
                report.resource_arn = f"acs:rds:{instance.region}:{rds_client.audited_account}:dbinstance/{instance.id}"

                if instance.log_disconnections == "on":
                    report.status = "PASS"
                    report.status_extended = f"RDS PostgreSQL Instance {instance.name} has log_disconnections enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS PostgreSQL Instance {instance.name} has log_disconnections disabled."

                findings.append(report)

        return findings
