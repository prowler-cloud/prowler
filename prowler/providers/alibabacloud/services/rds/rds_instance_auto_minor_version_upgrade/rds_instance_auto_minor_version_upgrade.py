"""
Check: rds_instance_auto_minor_version_upgrade

Ensures that RDS instances have automatic minor version upgrades enabled.
Auto minor version upgrades apply security patches and bug fixes automatically.

Risk Level: LOW
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_auto_minor_version_upgrade(Check):
    """Check if RDS instances have automatic minor version upgrades enabled"""

    def execute(self):
        """Execute the rds_instance_auto_minor_version_upgrade check"""
        findings = []

        for db_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=db_instance)
            report.account_uid = rds_client.account_id
            report.region = db_instance.region
            report.resource_id = db_instance.db_instance_id
            report.resource_arn = db_instance.arn

            if db_instance.auto_minor_version_upgrade:
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} has automatic minor version upgrades enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} does not have automatic minor version upgrades enabled. Enable auto upgrades for security patches."

            findings.append(report)

        return findings
