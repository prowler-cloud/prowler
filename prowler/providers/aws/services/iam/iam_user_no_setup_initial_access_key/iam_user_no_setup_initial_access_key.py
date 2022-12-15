from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_no_setup_initial_access_key(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for user_record in iam_client.credential_report:
            if (
                user_record["access_key_1_active"] == "true"
                and user_record["access_key_1_last_used_date"] == "N/A"
                and user_record["password_enabled"] == "true"
            ) or (
                user_record["access_key_2_active"] == "true"
                and user_record["access_key_2_last_used_date"] == "N/A"
                and user_record["password_enabled"] == "true"
            ):
                if (
                    user_record["access_key_1_active"] == "true"
                    and user_record["access_key_1_last_used_date"] == "N/A"
                    and user_record["password_enabled"] == "true"
                ):
                    report = Check_Report_AWS(self.metadata())
                    report.region = iam_client.region
                    report.resource_id = user_record["user"]
                    report.resource_arn = user_record["arn"]
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User {user_record['user']} has never used access key 1"
                    )
                    findings.append(report)
                if (
                    user_record["access_key_2_active"] == "true"
                    and user_record["access_key_2_last_used_date"] == "N/A"
                    and user_record["password_enabled"] == "true"
                ):
                    report = Check_Report_AWS(self.metadata())
                    report.region = iam_client.region
                    report.resource_id = user_record["user"]
                    report.resource_arn = user_record["arn"]
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User {user_record['user']} has never used access key 2"
                    )
                    findings.append(report)
            else:
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_id = user_record["user"]
                report.resource_arn = user_record["arn"]
                report.status = "PASS"
                report.status_extended = f"User {user_record['user']} does not have access keys or uses the access keys configured"
                findings.append(report)

        return findings
