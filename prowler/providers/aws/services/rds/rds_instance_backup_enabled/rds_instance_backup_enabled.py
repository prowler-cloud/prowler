from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_backup_enabled(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            if db_instance.backup_retention_period > 0:
                report.status = "PASS"
                report.status_extended = f"RDS Instance {db_instance.id} has backup enabled with retention period {db_instance.backup_retention_period} days."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} has not backup enabled."
                )

            findings.append(report)

        return findings
