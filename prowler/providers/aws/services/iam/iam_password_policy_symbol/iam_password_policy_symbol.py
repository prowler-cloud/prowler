from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_password_policy_symbol(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.region = iam_client.region
        report.resource_arn = iam_client.audited_account_arn
        report.resource_id = iam_client.audited_account
        # Check if password policy exists
        if iam_client.password_policy:
            # Check if symbol flag is set
            if iam_client.password_policy.symbols:
                report.status = "PASS"
                report.status_extended = (
                    "IAM password policy requires at least one symbol."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "IAM password policy does not require at least one symbol."
                )
        else:
            report.status = "FAIL"
            report.status_extended = "Password policy cannot be found."
        findings.append(report)
        return findings
