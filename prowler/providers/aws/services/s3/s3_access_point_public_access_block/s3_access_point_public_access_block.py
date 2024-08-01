from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class s3_access_point_public_access_block(Check):
    def execute(self):
        findings = []
        for access_point in s3control_client.access_points:
            report = Check_Report_AWS(self.metadata())
            report.region = s3control_client.region
            report.resource_id = s3control_client.audited_account
            report.resource_arn = s3_client.account_arn_template
            report.status = "PASS"
            report.status_extended = f"All Access Points in account {s3control_client.audited_account} have Public Access Block enabled."

            if not (
                access_point.public_access_block_configuration.block_public_acls
                and access_point.public_access_block_configuration.ignore_public_acls
                and access_point.public_access_block_configuration.block_public_policy
                and access_point.public_access_block_configuration.restrict_public_buckets
            ):
                report.status = "FAIL"
                report.status_extended = f"Account {s3control_client.audited_account} has at least one Access Point where Public Access Block is disabled."
                findings.append(report)
                break

            findings.append(report)

        return findings
