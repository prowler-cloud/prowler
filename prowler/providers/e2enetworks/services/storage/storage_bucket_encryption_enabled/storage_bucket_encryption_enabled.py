from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.storage.storage_client import storage_client


class storage_bucket_encryption_enabled(Check):
    """Check that object storage buckets have encryption enabled."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for bucket in storage_client.buckets:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=bucket)
            report.status = "PASS"
            report.status_extended = (
                f"Object storage bucket {bucket.name} has encryption enabled."
            )
            if not bucket.is_encryption_enabled:
                report.status = "FAIL"
                report.status_extended = f"Object storage bucket {bucket.name} does not have encryption enabled."
            findings.append(report)
        return findings
