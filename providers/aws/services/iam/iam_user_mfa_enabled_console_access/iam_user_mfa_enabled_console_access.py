from lib.check.models import Check, Check_Report
from providers.aws.services.iam.iam_service import iam_client


class iam_user_mfa_enabled_console_access(Check):
    def execute(self) -> Check_Report:
        findings = []
        response = iam_client.credential_report

        if response:
            for user in response:
                report = Check_Report(self.metadata)
                report.resource_id = user["user"]
                report.resource_arn = user["arn"]
                report.region = "us-east-1"
                if user["password_enabled"] != "not_supported":
                    if user["mfa_active"] == "false":
                        report.status = "FAIL"
                        report.status_extended = (
                            "User {user['user']} has Password enabled but MFA disabled."
                        )
                    else:
                        report.status = "PASS"
                        report.status_extended = f"User {user['user']} has Console Password enabled and MFA enabled."
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"User {user['user']} has not Console Password enabled."
                    )
                findings.append(report)
        else:
            report = Check_Report(self.metadata)
            report.status = "PASS"
            report.status_extended = "There is no IAM users."
            report.region = iam_client.region
            findings.append(report)

        return findings
