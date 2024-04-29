from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_password_policy_number(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.password_policy:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_arn = iam_client.password_policy_arn_template
            report.resource_id = iam_client.audited_account
            # Check if number flag is set
            if iam_client.password_policy.numbers:
                report.status = "PASS"
                report.status_extended = (
                    "IAM password policy requires at least one number."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "IAM password policy does not require at least one number."
                )
            findings.append(report)
        return findings
