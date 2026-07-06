from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.storage.storage_client import storage_client


class storage_bucket_public_access_disabled(Check):
    """Check that object storage buckets do not allow public access."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for bucket in storage_client.buckets:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=bucket)
            report.status = "PASS"
            report.status_extended = (
                f"Object storage bucket {bucket.name} does not allow public access."
            )
            if bucket.is_public_access_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Object storage bucket {bucket.name} allows public access."
                )
            findings.append(report)
        return findings
