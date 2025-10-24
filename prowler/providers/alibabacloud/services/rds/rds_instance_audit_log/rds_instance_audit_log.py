"""
Check: rds_instance_audit_log

Ensures that RDS instances have SQL audit logging enabled.
Audit logs record database operations for security monitoring and compliance.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_audit_log(Check):
    """Check if RDS instances have audit logging enabled"""

    def execute(self):
        """Execute the rds_instance_audit_log check"""
        findings = []

        for db_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=db_instance)
            report.account_uid = rds_client.account_id
            report.region = db_instance.region
            report.resource_id = db_instance.db_instance_id
            report.resource_arn = db_instance.arn

            if db_instance.audit_log_enabled:
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} has SQL audit logging enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS instance {db_instance.db_instance_name} does not have SQL audit logging enabled. Enable audit logging for security monitoring and compliance."

            findings.append(report)

        return findings
