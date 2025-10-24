"""
Check: rds_instance_ssl_enabled

Ensures that RDS instances have SSL/TLS enabled for encrypted connections.
SSL encrypts data in transit between applications and the database.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_ssl_enabled(Check):
    """Check if RDS instances have SSL enabled"""

    def execute(self):
        """Execute the rds_instance_ssl_enabled check"""
        findings = []

        for db_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=db_instance)
            report.account_uid = rds_client.account_id
            report.region = db_instance.region
            report.resource_id = db_instance.db_instance_id
            report.resource_arn = db_instance.arn

            if db_instance.ssl_enabled:
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} has SSL enabled for encrypted connections."
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} does not have SSL enabled. Enable SSL to encrypt data in transit."

            findings.append(report)

        return findings
