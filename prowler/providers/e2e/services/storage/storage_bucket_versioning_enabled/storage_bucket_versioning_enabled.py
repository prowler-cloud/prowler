from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.storage.storage_client import storage_client


class storage_bucket_versioning_enabled(Check):
    """Ensure object storage buckets have versioning enabled."""

    def execute(self) -> list[CheckReportE2e]:
        findings = []
        for bucket in storage_client.buckets:
            report = CheckReportE2e(metadata=self.metadata(), resource=bucket)
            report.status = "PASS"
            report.status_extended = (
                f"Object storage bucket {bucket.name} has versioning enabled."
            )
            if bucket.versioning_status != "Enabled":
                report.status = "FAIL"
                report.status_extended = (
                    f"Object storage bucket {bucket.name} does not have versioning enabled."
                )
            findings.append(report)
        return findings
