"""
Check: rds_instance_in_vpc

Ensures that RDS instances are deployed within a VPC.
Running databases in a VPC provides network isolation and enhanced security controls.

Risk Level: HIGH
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_in_vpc(Check):
    """Check if RDS instances are deployed in a VPC"""

    def execute(self):
        """Execute the rds_instance_in_vpc check"""
        findings = []

        for db_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=db_instance)
            report.account_uid = rds_client.account_id
            report.region = db_instance.region
            report.resource_id = db_instance.db_instance_id
            report.resource_arn = db_instance.arn

            if db_instance.vpc_id:
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} is deployed in VPC {db_instance.vpc_id}."
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} is not deployed in a VPC. Deploy the instance in a VPC for network isolation and enhanced security."

            findings.append(report)

        return findings
