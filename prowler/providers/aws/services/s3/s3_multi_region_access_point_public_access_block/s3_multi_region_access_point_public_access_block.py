from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class s3_multi_region_access_point_public_access_block(Check):
    def execute(self):
        findings = []
        for arn, mr_access_point in s3control_client.multi_region_access_points.keys():
            report = Check_Report_AWS(self.metadata())
            report.region = mr_access_point.region
            report.resource_id = mr_access_point.name
            report.resource_arn = mr_access_point.arn
            report.status = "PASS"
            report.status_extended = f"Multi Region Access Point {mr_access_point.name} of bucket {mr_access_point.bucket} does have Public Access Block enabled."

            if not (
                mr_access_point.public_access_block.block_public_acls
                and mr_access_point.public_access_block.ignore_public_acls
                and mr_access_point.public_access_block.block_public_policy
                and mr_access_point.public_access_block.restrict_public_buckets
            ):
                report.status = "FAIL"
                report.status_extended = f"Multi Region Access Point {mr_access_point.name} of bucket {mr_access_point.bucket} does not have Public Access Block enabled."

            findings.append(report)

        return findings
