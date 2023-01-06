from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_secure_transport_policy(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets:
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn
            # Check if bucket policy enforces SSL
            if not bucket.policy:
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} does not have a bucket policy, thus it allows HTTP requests."
            else:
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} allows requests over insecure transport in the bucket policy."
                for statement in bucket.policy["Statement"]:
                    if (
                        statement["Effect"] == "Deny"
                        and "Condition" in statement
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
