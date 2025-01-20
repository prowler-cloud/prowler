from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class cloudwatch_cross_account_sharing_disabled(Check):
    def execute(self):
        findings = []
        if iam_client.roles is not None:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=iam_client.roles
            )
            report.status = "PASS"
            report.status_extended = "CloudWatch doesn't allow cross-account sharing."
            report.region = iam_client.region
            report.resource_arn = iam_client.role_arn_template
            report.resource_id = iam_client.audited_account
            for role in iam_client.roles:
                if role.name == "CloudWatch-CrossAccountSharingRole":
                    report = Check_Report_AWS(metadata=self.metadata(), resource=role)
                    report.region = iam_client.region
                    report.status = "FAIL"
                    report.status_extended = (
                        "CloudWatch has allowed cross-account sharing."
                    )
            findings.append(report)
        return findings
