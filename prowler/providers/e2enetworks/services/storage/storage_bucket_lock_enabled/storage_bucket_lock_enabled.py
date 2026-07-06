from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.storage.storage_client import storage_client


class storage_bucket_lock_enabled(Check):
    """Check if E2E Networks object storage buckets have object lock enabled."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for bucket in storage_client.buckets:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=bucket)
            report.status = "PASS"
            report.status_extended = (
                f"Object storage bucket {bucket.name} has object lock enabled."
            )
            if not bucket.is_lock_enabled:
                report.status = "FAIL"
                report.status_extended = f"Object storage bucket {bucket.name} does not have object lock enabled."
            findings.append(report)
        return findings
