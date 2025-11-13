from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_bucket_encryption(Check):
    """
    Check if Object Storage buckets have encryption enabled.

    This check verifies that all StackIT Object Storage buckets
    have encryption at rest enabled to protect data.
    """

    def execute(self):
        """
        Execute the check for all buckets in the StackIT project.

        Returns:
            list: A list of CheckReportStackIT findings
        """
        findings = []

        for bucket in objectstorage_client.buckets:
            # Create a finding report for this bucket
            report = CheckReportStackIT(
                metadata=self.metadata(),
                resource=bucket,
            )

            # Set default status to PASS (encryption enabled)
            report.status = "PASS"
            report.status_extended = (
                f"Object Storage bucket '{bucket.name}' has encryption enabled."
            )

            # Check if encryption is disabled
            if not bucket.encryption_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Object Storage bucket '{bucket.name}' does not have encryption enabled."
                )

            findings.append(report)

        return findings
