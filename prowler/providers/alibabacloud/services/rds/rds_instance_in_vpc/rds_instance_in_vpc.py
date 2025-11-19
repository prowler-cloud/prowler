from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_in_vpc(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=db_instance
            )
            report.status = "FAIL"
            report.status_extended = (
                f"RDS instance {db_instance.db_instance_name} is not deployed in a VPC."
            )
            if db_instance.vpc_id:
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} is deployed in VPC {db_instance.vpc_id}."
            findings.append(report)
        return findings
