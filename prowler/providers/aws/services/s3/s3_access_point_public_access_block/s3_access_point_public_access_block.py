from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class s3_access_point_public_access_block(Check):
    def execute(self):
        findings = []
        for arn, access_point in s3control_client.access_points.items():
            report = Check_Report_AWS(self.metadata())
            report.region = access_point.region
            report.resource_id = access_point.name
            report.resource_arn = arn
            report.status = "PASS"
            report.status_extended = f"Access Point {access_point.name} of bucket {access_point.bucket} does have Public Access Block enabled."

            if not (
                access_point.public_access_block.block_public_acls
                and access_point.public_access_block.ignore_public_acls
                and access_point.public_access_block.block_public_policy
                and access_point.public_access_block.restrict_public_buckets
            ):
                report.status = "FAIL"
                report.status_extended = f"Access Point {access_point.name} of bucket {access_point.bucket} does not have Public Access Block enabled."

            findings.append(report)

        return findings
