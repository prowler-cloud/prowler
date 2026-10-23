from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_versioning_enabled(Check):
    """Check if versioning is enabled for OSS buckets."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for bucket in oss_client.buckets.values():
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if bucket.versioning_status == "Enabled":
                report.status = "PASS"
                report.status_extended = (
                    f"OSS bucket {bucket.name} has versioning enabled."
                )
            else:
                report.status = "FAIL"
                if bucket.versioning_status == "Suspended":
                    report.status_extended = (
                        f"OSS bucket {bucket.name} has versioning suspended."
                    )
                else:
                    report.status_extended = (
                        f"OSS bucket {bucket.name} does not have versioning enabled."
                    )

            findings.append(report)

        return findings
