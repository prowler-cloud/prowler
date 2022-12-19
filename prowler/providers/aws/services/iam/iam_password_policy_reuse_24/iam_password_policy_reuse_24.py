from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_password_policy_reuse_24(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.region = iam_client.region
        report.resource_id = "password_policy"
        # Check if password policy exists
        if iam_client.password_policy:
            # Check if reuse prevention flag is set
            if (
                iam_client.password_policy.reuse_prevention
                and iam_client.password_policy.reuse_prevention == 24
            ):
                report.status = "PASS"
                report.status_extended = (
                    "IAM password policy reuse prevention is equal to 24."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "IAM password policy reuse prevention is less than 24 or not set."
                )
        else:
            report.status = "FAIL"
            report.status_extended = "Password policy cannot be found"
        findings.append(report)
        return findings
