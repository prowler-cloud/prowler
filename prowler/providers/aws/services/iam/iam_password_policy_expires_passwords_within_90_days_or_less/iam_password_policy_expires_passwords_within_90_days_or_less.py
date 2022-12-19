from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_password_policy_expires_passwords_within_90_days_or_less(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.region = iam_client.region
        report.resource_id = "password_policy"
        # Check if password policy exists
        if iam_client.password_policy:
            # Check if password policy expiration exists
            if iam_client.password_policy.max_age:
                if iam_client.password_policy.max_age < 90:
                    report.status = "PASS"
                    report.status_extended = f"Password expiration is set lower than 90 days ({iam_client.password_policy.max_age} days)."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Password expiration is set greater than 90 days ({iam_client.password_policy.max_age} days)."
            else:
                report.status = "FAIL"
                report.status_extended = "Password expiration is not set."
        else:
            report.status = "FAIL"
            report.status_extended = "Password policy cannot be found."
        findings.append(report)

        return findings
