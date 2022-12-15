import datetime

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

maximum_access_days = 1


class iam_avoid_root_usage(Check):
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
                    user["password_last_used"] != "no_information"
                    or user["access_key_1_last_used_date"] != "N/A"
                    or user["access_key_2_last_used_date"] != "N/A"
                ):
                    if user["password_last_used"] != "no_information":
                        days_since_accessed = (
                            datetime.datetime.now()
                            - datetime.datetime.strptime(
                                user["password_last_used"],
                                "%Y-%m-%dT%H:%M:%S+00:00",
                            )
                        ).days
                    elif user["access_key_1_last_used_date"] != "N/A":
                        days_since_accessed = (
                            datetime.datetime.now()
                            - datetime.datetime.strptime(
                                user["access_key_1_last_used_date"],
                                "%Y-%m-%dT%H:%M:%S+00:00",
                            )
                        ).days
                    elif user["access_key_2_last_used_date"] != "N/A":
                        days_since_accessed = (
                            datetime.datetime.now()
                            - datetime.datetime.strptime(
                                user["access_key_2_last_used_date"],
                                "%Y-%m-%dT%H:%M:%S+00:00",
                            )
                        ).days
                    if days_since_accessed > maximum_access_days:
                        report.status = "FAIL"
                        report.status_extended = f"Root user in the account was last accessed {days_since_accessed} days ago."
                    else:
                        report.status = "PASS"
                        report.status_extended = f"Root user in the account wasn't accessed in the last {maximum_access_days} days."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Root user in the account wasn't accessed in the last {maximum_access_days} days."
                findings.append(report)

        return findings
