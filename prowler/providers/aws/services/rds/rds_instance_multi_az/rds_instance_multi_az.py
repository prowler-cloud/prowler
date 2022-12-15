from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_multi_az(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            if db_instance.multi_az:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} has multi-AZ enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} does not have multi-AZ enabled."
                )

            findings.append(report)

        return findings
