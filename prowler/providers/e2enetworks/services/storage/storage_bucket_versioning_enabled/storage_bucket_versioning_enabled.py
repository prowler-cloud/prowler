from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.storage.storage_client import storage_client


class storage_bucket_versioning_enabled(Check):
    """Check that object storage buckets have versioning enabled."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for bucket in storage_client.buckets:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=bucket)
            report.status = "PASS"
            report.status_extended = (
                f"Object storage bucket {bucket.name} has versioning enabled."
            )
            if bucket.versioning_status != "Enabled":
                report.status = "FAIL"
                report.status_extended = f"Object storage bucket {bucket.name} does not have versioning enabled."
            findings.append(report)
        return findings
