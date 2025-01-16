from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_cross_account_access(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=bucket
            )
            report.status = "PASS"
            report.status_extended = f"S3 Bucket {bucket.name} has a bucket policy but it does not allow cross account access."

            if not bucket.policy:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does not have a bucket policy."
                )
            elif is_policy_public(
                bucket.policy, s3_client.audited_account, is_cross_account_allowed=False
            ):
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} has a bucket policy allowing cross account access."

            findings.append(report)

        return findings
