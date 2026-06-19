from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.storage.storage_client import storage_client


class storage_bucket_encryption_enabled(Check):
    def execute(self):
        findings = []
        for bucket in storage_client.buckets:
            report = CheckReportE2e(metadata=self.metadata(), resource=bucket)
            report.status = "PASS"
            report.status_extended = (
                f"Object storage bucket {bucket.name} has encryption enabled."
            )
            if not bucket.is_encryption_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Object storage bucket {bucket.name} does not have encryption enabled."
                )
            findings.append(report)
        return findings
