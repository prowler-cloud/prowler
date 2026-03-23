from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_website_hosting_disabled(Check):
    """Ensure that S3 buckets do not have static website hosting enabled."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            if bucket.website_hosting_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has static website hosting enabled."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"S3 Bucket {bucket.name} does not have static website hosting enabled."
            findings.append(report)

        return findings
