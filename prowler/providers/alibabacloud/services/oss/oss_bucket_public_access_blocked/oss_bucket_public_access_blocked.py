"""
Check: oss_bucket_public_access_blocked

Ensures that OSS buckets block public access to prevent unauthorized data exposure.
Public buckets can be accessed by anyone on the internet, potentially exposing sensitive data.

Risk Level: CRITICAL
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_public_access_blocked(Check):
    """Check if OSS buckets block public access"""

    def execute(self):
        """Execute the oss_bucket_public_access_blocked check"""
        findings = []

        for bucket_arn, bucket in oss_client.buckets.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.account_uid = oss_client.account_id
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if not bucket.public_access:
                report.status = "PASS"
                report.status_extended = f"OSS bucket {bucket.name} blocks public access."
            else:
                report.status = "FAIL"
                report.status_extended = f"OSS bucket {bucket.name} allows public access. Configure bucket ACL to block public access to prevent unauthorized data exposure."

            findings.append(report)

        return findings
