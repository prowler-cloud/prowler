from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_deletion_protection(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=db_instance
            )
            report.status = "FAIL"
            report.status_extended = f"RDS instance {db_instance.db_instance_name} does not have deletion protection enabled."
            if db_instance.deletion_protection:
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} has deletion protection enabled."
            findings.append(report)
        return findings
