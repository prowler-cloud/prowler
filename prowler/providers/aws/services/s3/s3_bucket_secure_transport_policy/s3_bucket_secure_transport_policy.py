from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_secure_transport_policy(Check):
    """Ensure S3 bucket policies deny requests over insecure transport.

    - PASS: The bucket policy denies requests where aws:SecureTransport is false.
    - FAIL: The bucket has no policy, or its policy does not deny insecure transport.
    - MANUAL: The bucket policy could not be retrieved (missing permissions).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate the check.

        Returns:
            list[Check_Report_AWS]: One report per bucket.
        """
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            # Check if bucket policy enforces SSL
            if bucket.policy is None:
                report.status = "MANUAL"
                report.status_extended = f"Cannot evaluate secure transport for S3 Bucket {bucket.name}: the bucket policy could not be retrieved. Verify that the scanning credentials are allowed to call s3:GetBucketPolicy."
            elif not bucket.policy:
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} does not have a bucket policy, thus it allows HTTP requests."
            else:
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} allows requests over insecure transport in the bucket policy."
                for statement in bucket.policy["Statement"]:
                    if (
                        statement["Effect"] == "Deny"
                        and "Condition" in statement
                        and "Action" in statement
                        and (
                            "s3:PutObject" in statement["Action"]
                            or "*" in statement["Action"]
                            or "s3:*" in statement["Action"]
                        )
                    ):
                        if "Bool" in statement["Condition"]:
                            if "aws:SecureTransport" in statement["Condition"]["Bool"]:
                                if (
                                    statement["Condition"]["Bool"][
                                        "aws:SecureTransport"
                                    ]
                                    == "false"
                                ):
                                    report.status = "PASS"
                                    report.status_extended = f"S3 Bucket {bucket.name} has a bucket policy to deny requests over insecure transport."

            findings.append(report)
        return findings
