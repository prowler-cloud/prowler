import datetime

import pytz
from dateutil import parser

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

maximum_expiration_days = 90


class iam_rotate_access_key_90_days(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for user in iam_client.credential_report:
            # Search user in iam_client.users to get tags
            user_tags = []
            for iam_user in iam_client.users:
                if iam_user.arn == user["arn"]:
                    user_tags = iam_user.tags
                    break

            if (
                user["access_key_1_last_rotated"] == "N/A"
                and user["access_key_2_last_rotated"] == "N/A"
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_id = user["user"]
                report.resource_arn = user["arn"]
                report.resource_tags = user_tags
                report.status = "PASS"
                report.status_extended = (
                    f"User {user['user']} does not have access keys."
                )
                findings.append(report)

            else:
                old_access_keys = False
                if (
                    user["access_key_1_last_rotated"] != "N/A"
                    and user["access_key_1_active"] == "true"
                ):
                    access_key_1_last_rotated = datetime.datetime.now(
                        pytz.utc
                    ) - parser.parse(user["access_key_1_last_rotated"])
                    if access_key_1_last_rotated.days > maximum_expiration_days:
                        old_access_keys = True
                        report = Check_Report_AWS(self.metadata())
                        report.region = iam_client.region
                        report.resource_id = f"{user['user']}-access-key-1"
                        report.resource_arn = user["arn"]
                        report.resource_tags = user_tags
                        report.status = "FAIL"
                        report.status_extended = f"User {user['user']} has not rotated access key 1 in over 90 days ({access_key_1_last_rotated.days} days)."
                        findings.append(report)
                if (
                    user["access_key_2_last_rotated"] != "N/A"
                    and user["access_key_2_active"] == "true"
                ):
                    access_key_2_last_rotated = datetime.datetime.now(
                        pytz.utc
                    ) - parser.parse(user["access_key_2_last_rotated"])
                    if access_key_2_last_rotated.days > maximum_expiration_days:
                        old_access_keys = True
                        report = Check_Report_AWS(self.metadata())
                        report.region = iam_client.region
                        report.resource_id = f"{user['user']}-access-key-2"
                        report.resource_arn = user["arn"]
                        report.resource_tags = user_tags
                        report.status = "FAIL"
                        report.status_extended = f"User {user['user']} has not rotated access key 2 in over 90 days ({access_key_2_last_rotated.days} days)."
                        findings.append(report)

                if not old_access_keys:
                    report = Check_Report_AWS(self.metadata())
                    report.region = iam_client.region
                    report.resource_id = user["user"]
                    report.resource_arn = user["arn"]
                    report.resource_tags = user_tags
                    report.status = "PASS"
                    report.status_extended = f"User {user['user']} does not have access keys older than 90 days."
                    findings.append(report)

        return findings
