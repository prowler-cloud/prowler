"""
Check: oss_bucket_logging_enabled

Ensures that OSS buckets have access logging enabled for audit and compliance purposes.
Access logs provide detailed records of requests made to the bucket.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_logging_enabled(Check):
    """Check if OSS buckets have access logging enabled"""

    def execute(self):
        """Execute the oss_bucket_logging_enabled check"""
        findings = []

        for bucket_arn, bucket in oss_client.buckets.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.account_uid = oss_client.account_id
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if bucket.logging_enabled:
                report.status = "PASS"
                report.status_extended = f"OSS bucket {bucket.name} has access logging enabled (target: {bucket.access_logging_target})."
            else:
                report.status = "FAIL"
                report.status_extended = f"OSS bucket {bucket.name} does not have access logging enabled. Enable logging for audit and compliance purposes."

            findings.append(report)

        return findings
