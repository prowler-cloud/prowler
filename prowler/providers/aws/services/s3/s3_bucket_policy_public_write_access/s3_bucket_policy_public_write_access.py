from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_policy_public_write_access(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets:
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            # Check if bucket policy allow public write access
            if not bucket.policy:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does not have a bucket policy."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"S3 Bucket {bucket.name} does not allow public write access in the bucket policy."
                for statement in bucket.policy["Statement"]:
                    if (
                        statement["Effect"] == "Allow"
                        and "Condition" not in statement
                        and "*" in str(statement["Principal"])
                        and (
                            "s3:PutObject" in statement["Action"]
                            or "*" in statement["Action"]
                            or "s3:*" in statement["Action"]
                        )
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"S3 Bucket {bucket.name} allows public write access in the bucket policy.."

            findings.append(report)
        return findings
