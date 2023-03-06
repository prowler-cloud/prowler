import datetime

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

maximum_expiration_days = 90


class iam_disable_90_days_credentials(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for user in iam_client.users:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = user.name
            report.resource_arn = user.arn
            report.resource_tags = user.tags
            report.region = iam_client.region
            if user.password_last_used:
                time_since_insertion = (
                    datetime.datetime.now()
                    - datetime.datetime.strptime(
                        str(user.password_last_used), "%Y-%m-%d %H:%M:%S+00:00"
                    )
                )
                if time_since_insertion.days > maximum_expiration_days:
                    report.status = "FAIL"
                    report.status_extended = f"User {user.name} has not logged in to the console in the past {maximum_expiration_days} days."
                else:
                    report.status = "PASS"
                    report.status_extended = f"User {user.name} has logged in to the console in the past {maximum_expiration_days} days."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"User {user.name} does not have a console password or is unused."
                )

            # Append report
            findings.append(report)

        for user in iam_client.credential_report:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_id = user["user"]
            report.resource_arn = user["arn"]
            if (
                user["access_key_1_active"] != "true"
                and user["access_key_2_active"] != "true"
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"User {user['user']} does not have access keys."
                )
            else:
                old_access_keys = False
                if user["access_key_1_active"] == "true":
                    if user["access_key_1_last_used_date"] != "N/A":
                        access_key_1_last_used_date = (
                            datetime.datetime.now()
                            - datetime.datetime.strptime(
                                user["access_key_1_last_used_date"],
                                "%Y-%m-%dT%H:%M:%S+00:00",
                            )
                        )
                        if access_key_1_last_used_date.days > maximum_expiration_days:
                            old_access_keys = True
                            report.status = "FAIL"
                            report.status_extended = f"User {user['user']} has not used access key 1 in the last {maximum_expiration_days} days ({access_key_1_last_used_date.days} days)."

                if user["access_key_2_active"] == "true":
                    if user["access_key_2_last_used_date"] != "N/A":
                        access_key_2_last_used_date = (
                            datetime.datetime.now()
                            - datetime.datetime.strptime(
                                user["access_key_2_last_used_date"],
                                "%Y-%m-%dT%H:%M:%S+00:00",
                            )
                        )
                        if access_key_2_last_used_date.days > maximum_expiration_days:
                            old_access_keys = True
                            report.status = "FAIL"
                            report.status_extended = f"User {user['user']} has not used access key 2 in the last {maximum_expiration_days} days ({access_key_2_last_used_date.days} days)."

                if not old_access_keys:
                    report.status = "PASS"
                    report.status_extended = f"User {user['user']} does not have unused access keys for {maximum_expiration_days} days."
            findings.append(report)

        return findings
