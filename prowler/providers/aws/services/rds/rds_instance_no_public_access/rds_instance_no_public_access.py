from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_no_public_access(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            if not db_instance.public:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} is not Publicly Accessible."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} is set as Publicly Accessible."
                )

            findings.append(report)

        return findings
