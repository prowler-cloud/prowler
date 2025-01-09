from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class s3_multi_region_access_point_public_access_block(Check):
    """Ensure that Multi Region Access Points have Public Access Block enabled.

    This check is useful to ensure that Multi Region Access Points have Public Access Block enabled.
    """

    def execute(self):
        """Execute the Multi Region Access Points have Public Access Block enabled check.

        Iterates over all Multi Region Access Points and checks if they have Public Access Block enabled.

        Returns:
            List[Check_Report_AWS]: A list of reports for each Multi Region Access Point.
        """
        findings = []
        for mr_access_point in s3control_client.multi_region_access_points.values():
            report = Check_Report_AWS(self.metadata())
            report.region = mr_access_point.region
            report.resource_id = mr_access_point.name
            report.resource_arn = mr_access_point.arn
            report.status = "PASS"
            report.status_extended = f"S3 Multi Region Access Point {mr_access_point.name} of buckets {', '.join(mr_access_point.buckets)} does have Public Access Block enabled."

            if not (
                mr_access_point.public_access_block.block_public_acls
                and mr_access_point.public_access_block.ignore_public_acls
                and mr_access_point.public_access_block.block_public_policy
                and mr_access_point.public_access_block.restrict_public_buckets
            ):
                report.status = "FAIL"
                report.status_extended = f"S3 Multi Region Access Point {mr_access_point.name} of buckets {', '.join(mr_access_point.buckets)} does not have Public Access Block enabled."

            findings.append(report)

        return findings
