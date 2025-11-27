from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_logging_enabled(Check):
    """Check if logging is enabled for OSS buckets."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for bucket in oss_client.buckets.values():
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if bucket.logging_enabled:
                report.status = "PASS"
                if bucket.logging_target_bucket:
                    report.status_extended = (
                        f"OSS bucket {bucket.name} has logging enabled. "
                        f"Logs are stored in bucket '{bucket.logging_target_bucket}' "
                        f"with prefix {bucket.logging_target_prefix}."
                    )
                else:
                    report.status_extended = (
                        f"OSS bucket {bucket.name} has logging enabled."
                    )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"OSS bucket {bucket.name} does not have logging enabled."
                )

            findings.append(report)

        return findings
