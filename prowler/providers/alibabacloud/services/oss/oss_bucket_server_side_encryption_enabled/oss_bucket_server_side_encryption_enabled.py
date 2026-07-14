from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_server_side_encryption_enabled(Check):
    """Check if default server-side encryption is enabled for OSS buckets."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for bucket in oss_client.buckets.values():
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            algorithm = (bucket.encryption_algorithm or "").upper()
            if algorithm in {"AES256", "KMS", "SM4"}:
                report.status = "PASS"
                if bucket.encryption_kms_key_id:
                    report.status_extended = (
                        f"OSS bucket {bucket.name} has server-side encryption enabled "
                        f"with {bucket.encryption_algorithm} "
                        f"(KMS key {bucket.encryption_kms_key_id})."
                    )
                else:
                    report.status_extended = (
                        f"OSS bucket {bucket.name} has server-side encryption enabled "
                        f"with {bucket.encryption_algorithm}."
                    )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"OSS bucket {bucket.name} does not have default server-side encryption enabled."
                )

            findings.append(report)

        return findings
