import datetime

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

maximum_expiration_days = 90


class iam_rotate_access_key_90_days(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        response = iam_client.credential_report

        for user in response:
            if (
                user["access_key_1_last_rotated"] == "N/A"
                and user["access_key_2_last_rotated"] == "N/A"
            ):
                self.add_finding(
                    user=user,
                    status="PASS",
                    status_extended=f"User {user['user']} does not have access keys.",
                    findings=findings
                )
            else:
                old_access_keys = False
                if (
                    user["access_key_1_last_rotated"] != "N/A"
                    and user["access_key_1_active"] == "true"
                ):
                    access_key_1_last_rotated = (
                        datetime.datetime.now()
                        - datetime.datetime.strptime(
                            user["access_key_1_last_rotated"],
                            "%Y-%m-%dT%H:%M:%S+00:00",
                        )
                    )
                    if access_key_1_last_rotated.days > maximum_expiration_days:
                        old_access_keys = True
                        self.add_finding(
                            user=user,
                            status="FAIL",
                            status_extended=f"User {user['user']} has not rotated access key 1 in over 90 days ({access_key_1_last_rotated.days} days).",
                            findings=findings
                        )
                if (
                    user["access_key_2_last_rotated"] != "N/A"
                    and user["access_key_2_active"] == "true"
                ):
                    access_key_2_last_rotated = (
                        datetime.datetime.now()
                        - datetime.datetime.strptime(
                            user["access_key_2_last_rotated"],
                            "%Y-%m-%dT%H:%M:%S+00:00",
                        )
                    )
                    if access_key_2_last_rotated.days > maximum_expiration_days:
                        old_access_keys = True
                        self.add_finding(
                            user=user,
                            status="FAIL",
                            status_extended=f"User {user['user']} has not rotated access key 2 in over 90 days ({access_key_2_last_rotated.days} days).",
                            findings=findings
                        )
                if not old_access_keys:
                    self.add_finding(
                        user=user,
                        status="PASS",
                        status_extended=f"User {user['user']} does not have access keys older than 90 days.",
                        findings=findings
                    )

        return findings

    def add_finding(self, user, status, status_extended, findings):
        report = Check_Report_AWS(self.metadata())
        report.region = iam_client.region
        report.resource_id = user["user"]
        report.resource_arn = user["arn"]
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
