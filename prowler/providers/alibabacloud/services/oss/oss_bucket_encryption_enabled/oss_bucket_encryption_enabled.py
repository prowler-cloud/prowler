"""
Check: oss_bucket_encryption_enabled

Ensures that OSS buckets have server-side encryption enabled to protect data at rest.
Encryption protects sensitive data from unauthorized access.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_encryption_enabled(Check):
    """Check if OSS buckets have encryption enabled"""

    def execute(self):
        """Execute the oss_bucket_encryption_enabled check"""
        findings = []

        for bucket_arn, bucket in oss_client.buckets.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.account_uid = oss_client.account_id
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if bucket.encryption_enabled:
                report.status = "PASS"
                report.status_extended = f"OSS bucket {bucket.name} has server-side encryption enabled with {bucket.encryption_algorithm}."
            else:
                report.status = "FAIL"
                report.status_extended = f"OSS bucket {bucket.name} does not have server-side encryption enabled. Enable encryption to protect data at rest."

            findings.append(report)

        return findings
