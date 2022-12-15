import datetime

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

maximum_expiration_days = 90


class iam_rotate_access_key_90_days(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        response = iam_client.credential_report

        for user in response:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_id = user["user"]
            report.resource_arn = user["arn"]
            if (
                user["access_key_1_last_rotated"] == "N/A"
                and user["access_key_2_last_rotated"] == "N/A"
            ):
                report.status = "PASS"
                report.status_extended = f"User {user['user']} has not access keys."
            else:
                old_access_keys = False
                if user["access_key_1_last_rotated"] != "N/A":
                    access_key_1_last_rotated = (
                        datetime.datetime.now()
                        - datetime.datetime.strptime(
                            user["access_key_1_last_rotated"],
                            "%Y-%m-%dT%H:%M:%S+00:00",
                        )
                    )
                    if access_key_1_last_rotated.days > maximum_expiration_days:
                        old_access_keys = True
                        report.status = "FAIL"
                        report.status_extended = f"User {user['user']} has not rotated access key 1 in over 90 days ({access_key_1_last_rotated.days} days)."
                if user["access_key_2_last_rotated"] != "N/A":
                    access_key_2_last_rotated = (
                        datetime.datetime.now()
                        - datetime.datetime.strptime(
                            user["access_key_2_last_rotated"],
                            "%Y-%m-%dT%H:%M:%S+00:00",
                        )
                    )
                    if access_key_2_last_rotated.days > maximum_expiration_days:
                        old_access_keys = True
                        report.status = "FAIL"
                        report.status_extended = f"User {user['user']} has not rotated access key 2 in over 90 days ({access_key_2_last_rotated.days} days)."
                if not old_access_keys:
                    report.status = "PASS"
                    report.status_extended = (
                        f"User {user['user']} has access keys not older than 90 days."
                    )
            findings.append(report)

        return findings
