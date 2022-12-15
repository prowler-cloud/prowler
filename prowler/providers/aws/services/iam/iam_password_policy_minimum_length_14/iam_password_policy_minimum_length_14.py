from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_password_policy_minimum_length_14(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.region = iam_client.region
        report.resource_id = "password_policy"
        # Check if password policy exists
        if iam_client.password_policy:
            # Check password policy length
            if (
                iam_client.password_policy.length
                and iam_client.password_policy.length >= 14
            ):
                report.status = "PASS"
                report.status_extended = "IAM password policy does not requires minimum length of 14 characters."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "IAM password policy requires minimum length of 14 characters."
                )
        else:
            report.status = "FAIL"
            report.status_extended = "Password policy cannot be found"
        findings.append(report)
        return findings
