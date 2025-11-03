from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_versioning_enabled(Check):
    def execute(self):
        findings = []
        for bucket in oss_client.buckets.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=bucket
            )
            report.status = "FAIL"
            report.status_extended = (
                f"OSS bucket {bucket.name} does not have versioning enabled."
            )
            if bucket.versioning_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"OSS bucket {bucket.name} has versioning enabled."
                )
            findings.append(report)
        return findings
