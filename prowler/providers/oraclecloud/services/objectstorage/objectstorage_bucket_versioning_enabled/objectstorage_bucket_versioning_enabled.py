"""Check Ensure Versioning is Enabled for Object Storage Buckets."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_bucket_versioning_enabled(Check):
    """Check Ensure Versioning is Enabled for Object Storage Buckets."""

    def execute(self) -> Check_Report_OCI:
        """Execute the objectstorage_bucket_versioning_enabled check."""
        findings = []

        # Check buckets have versioning enabled
        for bucket in objectstorage_client.buckets:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=bucket,
                region=bucket.region,
                resource_name=bucket.name,
                resource_id=bucket.id,
                compartment_id=bucket.compartment_id,
            )

            if bucket.versioning and bucket.versioning == "Enabled":
                report.status = "PASS"
                report.status_extended = f"Bucket {bucket.name} has versioning enabled."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {bucket.name} does not have versioning enabled."
                )

            findings.append(report)

        return findings
