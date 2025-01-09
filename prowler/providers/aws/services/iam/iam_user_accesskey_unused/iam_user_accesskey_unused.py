import datetime

import pytz
from dateutil import parser

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_accesskey_unused(Check):
    def execute(self) -> Check_Report_AWS:
        maximum_expiration_days = iam_client.audit_config.get(
            "max_unused_access_keys_days", 45
        )
        findings = []
        for user in iam_client.credential_report:
            # Search user in iam_client.users to get tags
            user_tags = []
            for iam_user in iam_client.users:
                if iam_user.arn == user["arn"]:
                    user_tags = iam_user.tags
                    break

            if (
                user["access_key_1_active"] != "true"
                and user["access_key_2_active"] != "true"
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
                if user["access_key_1_active"] == "true":
                    if user["access_key_1_last_used_date"] != "N/A":
                        access_key_1_last_used_date = datetime.datetime.now(
                            pytz.utc
                        ) - parser.parse(user["access_key_1_last_used_date"])
                        if access_key_1_last_used_date.days > maximum_expiration_days:
                            old_access_keys = True
                            report = Check_Report_AWS(self.metadata())
                            report.region = iam_client.region
                            report.resource_id = user["user"] + "/AccessKey1"
                            report.resource_arn = user["arn"]
                            report.resource_tags = user_tags
                            report.status = "FAIL"
                            report.status_extended = f"User {user['user']} has not used access key 1 in the last {maximum_expiration_days} days ({access_key_1_last_used_date.days} days)."
                            findings.append(report)

                if user["access_key_2_active"] == "true":
                    if user["access_key_2_last_used_date"] != "N/A":
                        access_key_2_last_used_date = datetime.datetime.now(
                            pytz.utc
                        ) - parser.parse(user["access_key_2_last_used_date"])
                        if access_key_2_last_used_date.days > maximum_expiration_days:
                            old_access_keys = True
                            report = Check_Report_AWS(self.metadata())
                            report.region = iam_client.region
                            report.resource_id = user["user"] + "/AccessKey2"
                            report.resource_arn = user["arn"]
                            report.resource_tags = user_tags
                            report.status = "FAIL"
                            report.status_extended = f"User {user['user']} has not used access key 2 in the last {maximum_expiration_days} days ({access_key_2_last_used_date.days} days)."
                            findings.append(report)

                if not old_access_keys:
                    report = Check_Report_AWS(self.metadata())
                    report.region = iam_client.region
                    report.resource_id = user["user"]
                    report.resource_arn = user["arn"]
                    report.resource_tags = user_tags
                    report.status = "PASS"
                    report.status_extended = f"User {user['user']} does not have unused access keys for {maximum_expiration_days} days."
                    findings.append(report)

        return findings
