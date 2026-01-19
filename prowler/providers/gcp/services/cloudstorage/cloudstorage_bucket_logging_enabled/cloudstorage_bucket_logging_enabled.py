from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import (
    cloudstorage_client,
)


class cloudstorage_bucket_logging_enabled(Check):
    """
    Ensure Cloud Storage buckets have Usage and Storage Logs enabled.

    Reports PASS if a bucket has logging configured (logBucket defined),
    otherwise FAIL.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        for bucket in cloudstorage_client.buckets:
            report = Check_Report_GCP(metadata=self.metadata(), resource=bucket)
            report.status = "FAIL"
            report.status_extended = (
                f"Bucket {bucket.name} does not have Usage and Storage Logs enabled."
            )

            if bucket.logging_bucket:
                report.status = "PASS"
                if bucket.logging_prefix:
                    report.status_extended = (
                        f"Bucket {bucket.name} has Usage and Storage Logs enabled. "
                        f"Logs are stored in bucket '{bucket.logging_bucket}' with prefix '{bucket.logging_prefix}'."
                    )
                else:
                    report.status_extended = (
                        f"Bucket {bucket.name} has Usage and Storage Logs enabled. "
                        f"Logs are stored in bucket '{bucket.logging_bucket}' with default prefix."
                    )

            findings.append(report)

        return findings
