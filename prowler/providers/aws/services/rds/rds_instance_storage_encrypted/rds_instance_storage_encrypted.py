from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_storage_encrypted(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=db_instance
            )
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
