"""Check Ensure Object Storage Buckets are encrypted with a Customer Managed Key (CMK)."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_bucket_encrypted_with_cmk(Check):
    """Check Ensure Object Storage Buckets are encrypted with a Customer Managed Key (CMK)."""

    def execute(self) -> Check_Report_OCI:
        """Execute the objectstorage_bucket_encrypted_with_cmk check."""
        findings = []

        # Check buckets are encrypted with CMK
        for bucket in objectstorage_client.buckets:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=bucket,
                region=bucket.region,
                resource_name=bucket.name,
                resource_id=bucket.id,
                compartment_id=bucket.compartment_id,
            )

            if bucket.kms_key_id:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {bucket.name} is encrypted with Customer Managed Key."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {bucket.name} is not encrypted with Customer Managed Key."
                )

            findings.append(report)

        return findings
