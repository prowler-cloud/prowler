from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_cross_account_access(Check):
    def execute(self):
        findings = []
        trusted_account_ids = s3_client.audit_config.get("trusted_account_ids", [])
        for bucket in s3_client.buckets.values():
            if bucket.policy is None:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            report.status = "PASS"
            report.status_extended = f"S3 Bucket {bucket.name} has a bucket policy but it does not allow cross account access."

            if not bucket.policy:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does not have a bucket policy."
                )
            elif is_policy_public(
                bucket.policy,
                s3_client.audited_account,
                is_cross_account_allowed=False,
                trusted_account_ids=trusted_account_ids,
            ):
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} has a bucket policy allowing cross account access."

            findings.append(report)

        return findings
