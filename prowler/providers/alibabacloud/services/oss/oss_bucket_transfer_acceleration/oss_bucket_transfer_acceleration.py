"""
Check: oss_bucket_transfer_acceleration

Checks if OSS buckets have transfer acceleration enabled for improved global data transfer performance.
Transfer acceleration uses optimized network paths for faster uploads/downloads from distant locations.

Risk Level: INFORMATIONAL
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_transfer_acceleration(Check):
    """Check if OSS buckets have transfer acceleration enabled"""

    def execute(self):
        """Execute the oss_bucket_transfer_acceleration check"""
        findings = []

        for bucket_arn, bucket in oss_client.buckets.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.account_uid = oss_client.account_id
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if bucket.transfer_acceleration:
                report.status = "PASS"
                report.status_extended = f"OSS bucket {bucket.name} has transfer acceleration enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"OSS bucket {bucket.name} does not have transfer acceleration enabled. Consider enabling transfer acceleration for improved global data transfer performance."

            findings.append(report)

        return findings
