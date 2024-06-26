from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_storage_encrypted(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance.arn
            report.resource_tags = db_instance.tags
            if db_instance.encrypted:
                report.status = "PASS"
                report.status_extended = f"RDS Instance {db_instance.id} is encrypted."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} is not encrypted."
                )

            findings.append(report)

        return findings
