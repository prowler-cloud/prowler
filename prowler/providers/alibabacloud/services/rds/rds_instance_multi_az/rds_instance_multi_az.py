from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_multi_az(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=db_instance
            )
            report.status = "FAIL"
            report.status_extended = f"RDS instance {db_instance.db_instance_name} is not deployed across multiple availability zones."
            if db_instance.multi_az:
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} is deployed across multiple availability zones."
            findings.append(report)
        return findings
