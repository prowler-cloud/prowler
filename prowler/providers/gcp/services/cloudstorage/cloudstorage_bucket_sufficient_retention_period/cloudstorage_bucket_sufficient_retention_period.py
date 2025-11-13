from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import (
    cloudstorage_client,
)


class cloudstorage_bucket_sufficient_retention_period(Check):
    """
    Ensure there is a sufficient bucket-level retention period configured for GCS buckets.

    PASS: retentionPolicy.retentionPeriod >= min threshold (days)
    FAIL: no retention policy or period < threshold
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        min_retention_days = int(
            getattr(cloudstorage_client, "audit_config", {}).get(
                "storage_min_retention_days", 90
            )
        )

        for bucket in cloudstorage_client.buckets:
            report = Check_Report_GCP(metadata=self.metadata(), resource=bucket)

            retention_policy = bucket.retention_policy

            if retention_policy is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {bucket.name} does not have a retention policy "
                    f"(minimum required: {min_retention_days} days)."
                )
                findings.append(report)
                continue

            days = retention_policy.retention_period // 86400  # seconds to days

            if days >= min_retention_days:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {bucket.name} has a sufficient retention policy of {days} days "
                    f"(minimum required: {min_retention_days})."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {bucket.name} has an insufficient retention policy of {days} days "
                    f"(minimum required: {min_retention_days})."
                )

            findings.append(report)

        return findings
