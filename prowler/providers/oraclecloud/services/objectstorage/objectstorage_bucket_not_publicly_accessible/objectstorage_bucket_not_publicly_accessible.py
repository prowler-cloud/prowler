"""Check if Object Storage buckets are not publicly accessible."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_bucket_not_publicly_accessible(Check):
    """Check if Object Storage buckets are not publicly accessible."""

    def execute(self) -> Check_Report_OCI:
        """Execute the objectstorage_bucket_not_publicly_accessible check.

        Returns:
            List of Check_Report_OCI objects with findings
        """
        findings = []

        for bucket in objectstorage_client.buckets:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=bucket,
                region=bucket.region,
                resource_name=bucket.name,
                resource_id=bucket.id,
                compartment_id=bucket.compartment_id,
            )

            # Check if bucket has public access
            # NoPublicAccess means the bucket is not publicly accessible
            if bucket.public_access_type == "NoPublicAccess":
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {bucket.name} is not publicly accessible."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Bucket {bucket.name} has public access type: {bucket.public_access_type}."

            findings.append(report)

        return findings
