"""
Check: oss_bucket_versioning_enabled

Ensures that OSS buckets have versioning enabled to protect against accidental deletions and overwrites.
Versioning allows recovery of objects from accidental deletion or overwrite.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_versioning_enabled(Check):
    """Check if OSS buckets have versioning enabled"""

    def execute(self):
        """Execute the oss_bucket_versioning_enabled check"""
        findings = []

        for bucket_arn, bucket in oss_client.buckets.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.account_uid = oss_client.account_id
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if bucket.versioning_enabled:
                report.status = "PASS"
                report.status_extended = f"OSS bucket {bucket.name} has versioning enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"OSS bucket {bucket.name} does not have versioning enabled. Enable versioning to protect against accidental deletions and overwrites."

            findings.append(report)

        return findings
