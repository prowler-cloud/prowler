"""
Check: rds_instance_multi_az

Ensures that RDS instances are deployed across multiple availability zones for high availability.
Multi-AZ deployments provide enhanced database availability and durability.

Risk Level: MEDIUM
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_multi_az(Check):
    """Check if RDS instances are deployed in multiple availability zones"""

    def execute(self):
        """Execute the rds_instance_multi_az check"""
        findings = []

        for db_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=db_instance)
            report.account_uid = rds_client.account_id
            report.region = db_instance.region
            report.resource_id = db_instance.db_instance_id
            report.resource_arn = db_instance.arn

            if db_instance.multi_az:
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} is deployed across multiple availability zones."
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} is not deployed across multiple availability zones. Enable Multi-AZ for high availability."

            findings.append(report)

        return findings
