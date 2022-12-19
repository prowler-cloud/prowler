from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class s3_account_level_public_access_blocks(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = f"Block Public Access is not configured for the account {s3_client.audited_account}."
        report.region = s3control_client.region
        report.resource_id = s3_client.audited_account
        if (
            s3control_client.account_public_access_block
            and s3control_client.account_public_access_block.ignore_public_acls
            and s3control_client.account_public_access_block.restrict_public_buckets
        ):
            report.status = "PASS"
            report.status_extended = f"Block Public Access is configured for the account {s3_client.audited_account}."

        findings.append(report)

        return findings
