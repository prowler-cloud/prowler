from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class s3_bucket_policy_public_write_access(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets.values():
            if bucket.policy is None:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
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
                if is_policy_public(
                    bucket.policy,
                    s3_client.audited_account,
                    not_allowed_actions=[
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:*",
                        "s3:Put*",
                        "s3:Delete*",
                    ],
                ):
                    report.status = "FAIL"
                    report.status_extended = f"S3 Bucket {bucket.name} allows public write access in the bucket policy."

            findings.append(report)
        return findings
