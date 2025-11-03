from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import (
    cloudstorage_client,
)


class cloudstorage_bucket_versioning_enabled(Check):
    """
    Ensure Cloud Storage buckets have Object Versioning enabled.

    Reports PASS if a bucket has versioning enabled, otherwise FAIL.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for bucket in cloudstorage_client.buckets:
            report = Check_Report_GCP(metadata=self.metadata(), resource=bucket)
            report.status = "FAIL"
            report.status_extended = (
                f"Bucket {bucket.name} does not have Object Versioning enabled."
            )

            if bucket.versioning_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {bucket.name} has Object Versioning enabled."
                )

            findings.append(report)
        return findings
