from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.storage.storage_client import storage_client


class storage_bucket_lifecycle_configured(Check):
    """Check if E2E Networks object storage buckets have lifecycle configuration enabled."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for bucket in storage_client.buckets:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=bucket)
            report.status = "PASS"
            report.status_extended = f"Object storage bucket {bucket.name} has lifecycle configuration enabled."
            if bucket.lifecycle_configuration_status != "Configured":
                report.status = "FAIL"
                report.status_extended = f"Object storage bucket {bucket.name} does not have lifecycle configuration enabled."
            findings.append(report)
        return findings
