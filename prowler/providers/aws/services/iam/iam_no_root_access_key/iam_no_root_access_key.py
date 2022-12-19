from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_no_root_access_key(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        response = iam_client.credential_report

        for user in response:
            if user["user"] == "<root_account>":
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_id = user["user"]
                report.resource_arn = user["arn"]
                if (
                    user["access_key_1_active"] == "false"
                    and user["access_key_2_active"] == "false"
                ):
                    report.status = "PASS"
                    report.status_extended = f"User {user['user']} has not access keys."
                elif (
                    user["access_key_1_active"] == "true"
                    and user["access_key_2_active"] == "true"
                ):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User {user['user']} has two active access keys."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User {user['user']} has one active access key."
                    )
                findings.append(report)

        return findings
