from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_minor_version_upgrade_enabled(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=db_instance
            )
            if db_instance.auto_minor_version_upgrade:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} has minor version upgrade enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS Instance {db_instance.id} does not have minor version upgrade enabled."

            findings.append(report)

        return findings
