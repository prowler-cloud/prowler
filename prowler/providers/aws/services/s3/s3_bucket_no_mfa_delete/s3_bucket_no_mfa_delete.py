from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_no_mfa_delete(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets:
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            if bucket.mfa_delete:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has MFA Delete enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has MFA Delete disabled."
                )
            findings.append(report)

        return findings
