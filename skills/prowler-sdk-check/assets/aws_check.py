# Example: AWS S3 bucket object versioning check (PASS / FAIL / no finding)
# Based on: prowler/providers/aws/services/s3/s3_bucket_object_versioning/s3_bucket_object_versioning.py

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_object_versioning(Check):
    """Ensure S3 buckets have object versioning enabled.

    - PASS: Versioning is enabled.
    - FAIL: Versioning is disabled.
    - No finding: The versioning configuration could not be retrieved (missing
      permissions). Never MANUAL; the service already logged the error.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate versioning for every audited bucket.

        Returns:
            list[Check_Report_AWS]: One report per bucket whose versioning could be read.
        """
        findings = []
        for bucket in s3_client.buckets.values():
            if not bucket.versioning_retrieved:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            if bucket.versioning:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has versioning enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has versioning disabled."
                )
            findings.append(report)

        return findings
