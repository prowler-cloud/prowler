from lib.check.models import Check, Check_Report
from providers.aws.services.iam.iam_client import iam_client


class iam_password_policy_lowercase(Check):
    def execute(self) -> Check_Report:
        findings = []
        report = Check_Report(self.metadata)
        report.region = iam_client.region
        report.resource_id = "password_policy"
        # Check if password policy exists
        if iam_client.password_policy:
            # Check if lowercase flag is set
            if iam_client.password_policy.lowercase:
                report.status = "PASS"
                report.status_extended = (
                    f"Password lowercase option in password policy is set."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Password lowercase option in password policy is not set."
                )
        else:
            report.status = "FAIL"
            report.status_extended = f"Password policy cannot be found"
        findings.append(report)
        return findings
