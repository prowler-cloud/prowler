from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.storage.storage_client import storage_client


class storage_bucket_public_access_disabled(Check):
    def execute(self):
        findings = []
        for bucket in storage_client.buckets:
            report = CheckReportE2e(metadata=self.metadata(), resource=bucket)
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
