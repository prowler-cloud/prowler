from lib.check.models import Check, Check_Report
from providers.aws.services.iam.iam_service import iam_client


class iam_user_two_active_access_key(Check):
    def execute(self) -> Check_Report:
        findings = []
        response = iam_client.credential_report
        for user in response:
            report = Check_Report(self.metadata)
            report.resource_id = user["user"]
            report.resource_arn = user["arn"]
            report.region = "us-east-1"
            if (
                user["access_key_1_active"] == "true"
                and user["access_key_2_active"] == "true"
            ):
                report.status = "FAIL"
                report.status_extended = (
                    f"User {user['user']} has 2 active access keys."
                )
                findings.append(report)
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"User {user['user']} has not 2 active access keys."
                )
                findings.append(report)

        return findings
