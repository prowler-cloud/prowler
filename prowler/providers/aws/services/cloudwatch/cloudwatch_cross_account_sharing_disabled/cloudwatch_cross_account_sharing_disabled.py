from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class cloudwatch_cross_account_sharing_disabled(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "PASS"
        report.status_extended = "CloudWatch doesn't allows cross-account sharing"
        report.resource_id = "CloudWatch-CrossAccountSharingRole"
        report.region = iam_client.region
        for role in iam_client.roles:
            if role.name == "CloudWatch-CrossAccountSharingRole":
                report.resource_arn = role.arn
                report.status = "FAIL"
                report.status_extended = "CloudWatch has allowed cross-account sharing."
        findings.append(report)
        return findings
