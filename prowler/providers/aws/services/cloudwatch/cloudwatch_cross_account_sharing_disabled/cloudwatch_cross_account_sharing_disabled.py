from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class cloudwatch_cross_account_sharing_disabled(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "PASS"
        report.status_extended = "CloudWatch doesn't allow cross-account sharing."
        report.resource_arn = iam_client.role_arn_template
        report.resource_id = iam_client.audited_account
        report.region = iam_client.region
        for role in iam_client.roles:
            if role.name == "CloudWatch-CrossAccountSharingRole":
                report.resource_arn = role.arn
                report.resource_id = role.name
                report.status = "FAIL"
                report.status_extended = "CloudWatch has allowed cross-account sharing."
        findings.append(report)
        return findings
