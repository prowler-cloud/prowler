from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_deletion_protection(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            if db_instance.deletion_protection:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} deletion protection is enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} deletion protection is not enabled."
                )

            findings.append(report)

        return findings
