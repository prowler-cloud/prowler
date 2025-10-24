"""
Check: rds_instance_deletion_protection

Ensures that RDS instances have deletion protection enabled.
Deletion protection prevents accidental deletion of database instances.

Risk Level: MEDIUM
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_deletion_protection(Check):
    """Check if RDS instances have deletion protection enabled"""

    def execute(self):
        """Execute the rds_instance_deletion_protection check"""
        findings = []

        for db_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=db_instance)
            report.account_uid = rds_client.account_id
            report.region = db_instance.region
            report.resource_id = db_instance.db_instance_id
            report.resource_arn = db_instance.arn

            if db_instance.deletion_protection:
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} has deletion protection enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} does not have deletion protection enabled. Enable deletion protection to prevent accidental deletion."

            findings.append(report)

        return findings
