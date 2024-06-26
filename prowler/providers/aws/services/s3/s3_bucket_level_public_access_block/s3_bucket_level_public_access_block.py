from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class s3_bucket_level_public_access_block(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets:
            if bucket.public_access_block:
                report = Check_Report_AWS(self.metadata())
                report.region = bucket.region
                report.resource_id = bucket.name
                report.resource_arn = bucket.arn
                report.resource_tags = bucket.tags
                report.status = "PASS"
                report.status_extended = f"Block Public Access is configured for the S3 Bucket {bucket.name}."
                if not (
                    bucket.public_access_block.ignore_public_acls
                    and bucket.public_access_block.restrict_public_buckets
                ):
                    if (
                        s3control_client.account_public_access_block
                        and s3control_client.account_public_access_block.ignore_public_acls
                        and s3control_client.account_public_access_block.restrict_public_buckets
                    ):
                        report.status_extended = f"Block Public Access is configured for the S3 Bucket {bucket.name} at account {s3_client.audited_account} level."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Block Public Access is not configured for the S3 Bucket {bucket.name}."
                findings.append(report)
        return findings
