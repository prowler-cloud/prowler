from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_default_encryption_kms(Check):
    def execute(self):
        findings = []
        for bucket in oss_client.buckets.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=bucket
            )
            report.status = "FAIL"
            if bucket.encryption_enabled and bucket.encryption_algorithm:
                if "KMS" in bucket.encryption_algorithm.upper():
                    report.status = "PASS"
                    report.status_extended = (
                        f"OSS bucket {bucket.name} uses KMS for encryption."
                    )
                else:
                    report.status_extended = f"OSS bucket {bucket.name} uses {bucket.encryption_algorithm} for encryption."
            else:
                report.status_extended = (
                    f"OSS bucket {bucket.name} does not have encryption enabled."
                )
            findings.append(report)
        return findings
