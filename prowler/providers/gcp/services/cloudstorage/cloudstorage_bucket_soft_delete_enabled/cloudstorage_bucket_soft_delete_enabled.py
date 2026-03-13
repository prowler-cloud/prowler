from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import (
    cloudstorage_client,
)


class cloudstorage_bucket_soft_delete_enabled(Check):
    """
    Ensure Cloud Storage buckets have Soft Delete enabled.

    Reports PASS if a bucket has Soft Delete enabled (retentionDurationSeconds > 0),
    otherwise FAIL.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for bucket in cloudstorage_client.buckets:
            report = Check_Report_GCP(metadata=self.metadata(), resource=bucket)
            report.status = "FAIL"
            report.status_extended = (
                f"Bucket {bucket.name} does not have Soft Delete enabled."
            )

            if bucket.soft_delete_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {bucket.name} has Soft Delete enabled."
                )

            findings.append(report)
        return findings
