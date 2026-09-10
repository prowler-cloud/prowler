from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_object_versioning(Check):
    """Ensure S3 buckets have object versioning enabled.

    - PASS: Versioning is enabled.
    - FAIL: Versioning is disabled.
    - MANUAL: The versioning configuration could not be retrieved (missing
      permissions), so the status cannot be asserted.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate versioning for every audited bucket.

        Returns:
            list[Check_Report_AWS]: One report per bucket.
        """
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            if not bucket.versioning_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Cannot evaluate versioning for S3 Bucket {bucket.name}: the versioning configuration could not be retrieved. Verify that the scanning credentials are allowed to call s3:GetBucketVersioning."
            elif bucket.versioning:
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
