"""
Check: oss_bucket_default_encryption_kms

Ensures that OSS buckets use KMS (Key Management Service) for encryption instead of AES256.
KMS provides better key management, rotation, and audit capabilities compared to AES256.

Risk Level: LOW
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_default_encryption_kms(Check):
    """Check if OSS buckets use KMS for encryption"""

    def execute(self):
        """Execute the oss_bucket_default_encryption_kms check"""
        findings = []

        for bucket_arn, bucket in oss_client.buckets.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.account_uid = oss_client.account_id
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if bucket.encryption_enabled and bucket.encryption_algorithm:
                if "KMS" in bucket.encryption_algorithm.upper():
                    report.status = "PASS"
                    report.status_extended = f"OSS bucket {bucket.name} uses KMS for server-side encryption."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"OSS bucket {bucket.name} uses {bucket.encryption_algorithm} for encryption. Consider using KMS for better key management and audit capabilities."
            else:
                report.status = "FAIL"
                report.status_extended = f"OSS bucket {bucket.name} does not have encryption enabled. Enable KMS encryption for better security."

            findings.append(report)

        return findings
