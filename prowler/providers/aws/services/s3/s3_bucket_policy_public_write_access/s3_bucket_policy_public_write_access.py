from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class s3_bucket_policy_public_write_access(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets:
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn
            report.resource_tags = bucket.tags
            # Check if bucket policy allow public write access
            if not bucket.policy:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does not have a bucket policy."
                )
            elif (
                s3control_client.account_public_access_block
                and s3control_client.account_public_access_block.restrict_public_buckets
            ):
                report.status = "PASS"
                report.status_extended = (
                    "All S3 public access blocked at account level."
                )
            elif (
                bucket.public_access_block
                and bucket.public_access_block.restrict_public_buckets
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"S3 public access blocked at bucket level for {bucket.name}."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"S3 Bucket {bucket.name} does not allow public write access in the bucket policy."
                for statement in bucket.policy["Statement"]:
                    if (
                        statement["Effect"] == "Allow"
                        and "Condition" not in statement
                        and (
                            "Principal" in statement
                            and "*" in str(statement["Principal"])
                        )
                        and (
                            (
                                isinstance(statement["Action"], list)
                                and (
                                    "s3:PutObject" in statement["Action"]
                                    or "*" in statement["Action"]
                                    or "s3:*" in statement["Action"]
                                    or "s3:Put*" in statement["Action"]
                                )
                            )
                            or (
                                isinstance(statement["Action"], str)
                                and (
                                    "s3:PutObject" == statement["Action"]
                                    or "*" == statement["Action"]
                                    or "s3:*" == statement["Action"]
                                    or "s3:Put*" == statement["Action"]
                                )
                            )
                        )
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"S3 Bucket {bucket.name} allows public write access in the bucket policy."

            findings.append(report)
        return findings
