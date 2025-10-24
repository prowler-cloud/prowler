"""
Check: rds_instance_encryption

Ensures that RDS instances have Transparent Data Encryption (TDE) enabled.
Encryption protects sensitive database data at rest.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_encryption(Check):
    """Check if RDS instances have encryption enabled"""

    def execute(self):
        """Execute the rds_instance_encryption check"""
        findings = []

        for db_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=db_instance)
            report.account_uid = rds_client.account_id
            report.region = db_instance.region
            report.resource_id = db_instance.db_instance_id
            report.resource_arn = db_instance.arn

            if db_instance.encryption_enabled:
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} has Transparent Data Encryption (TDE) enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} does not have Transparent Data Encryption (TDE) enabled. Enable TDE to protect data at rest."

            findings.append(report)

        return findings
