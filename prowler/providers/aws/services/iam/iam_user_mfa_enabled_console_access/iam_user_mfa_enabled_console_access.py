from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_mfa_enabled_console_access(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        response = iam_client.credential_report
        for user in response:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = user["user"]
            report.resource_arn = user["arn"]
            report.region = iam_client.region
            # all the users but root (which by default does not support console password)
            if user["password_enabled"] != "not_supported":
                # check if the user has password enabled
                if user["password_enabled"] == "true":
                    if user["mfa_active"] == "false":
                        report.status = "FAIL"
                        report.status_extended = f"User {user['user']} has Console Password enabled but MFA disabled."
                    else:
                        report.status = "PASS"
                        report.status_extended = f"User {user['user']} has Console Password enabled and MFA enabled."
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"User {user['user']} has not Console Password enabled."
                    )
            # root user
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"User {user['user']} has not Console Password enabled."
                )
            findings.append(report)

        return findings
