from lib.check.models import Check, Check_Report
from providers.aws.services.s3.s3_client import s3_client


class s3_bucket_default_encryption(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets:
            report = Check_Report(self.metadata)
            report.region = bucket.region
            report.resource_id = bucket.name
            if not bucket.encryption:
                report.status = "FAIL"
                report.status_extended = f"Server Side Encryption configuration is not configured for S3 Bucket {bucket.name}."
            else:
                # Check if bucket policy enforce SSE
                if not bucket.policy:
                    report.status = "FAIL"
                    report.status_extended = f"Bucket {bucket.name} has default encryption with {bucket.encryption} but does not have a bucket policy."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Bucket {bucket.name} has default encryption with {bucket.encryption} but does not enforce it in the bucket policy."
                    for statement in bucket.policy["Statement"]:
                        if (
                            statement["Effect"] == "Deny"
                            and "Condition" in statement
                            and ("s3:PutObject" in statement["Action"] or "*" in statement["Action"] or "s3:*" in statement["Action"])
                        ):
                            if "StringNotEquals" in statement["Condition"]:
                                if (
                                    "s3:x-amz-server-side-encryption"
                                    in statement["Condition"]["StringNotEquals"]
                                ):
                                    if (
                                        statement["Condition"]["StringNotEquals"][
                                            "s3:x-amz-server-side-encryption"
                                        ]
                                        == bucket.encryption
                                    ):
                                        report.status = "PASS"
                                        report.status_extended = f"Bucket {bucket.name} enforces default encryption with {bucket.encryption}."

            findings.append(report)
        return findings
