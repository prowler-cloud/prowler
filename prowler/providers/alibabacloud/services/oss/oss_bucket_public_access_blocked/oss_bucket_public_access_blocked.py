from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_public_access_blocked(Check):
    def execute(self):
        findings = []
        for bucket in oss_client.buckets.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=bucket
            )
            report.status = "FAIL"
            report.status_extended = f"OSS bucket {bucket.name} allows public access."
            if not bucket.public_access:
                report.status = "PASS"
                report.status_extended = (
                    f"OSS bucket {bucket.name} blocks public access."
                )
            findings.append(report)
        return findings
