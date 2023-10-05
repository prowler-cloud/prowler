import datetime

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

maximum_expiration_days = iam_client.audit_config.get("max_console_access_days")


class iam_user_console_access_unused(Check):
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
                    report.status_extended = f"User {user.name} has not logged in to the console in the past {maximum_expiration_days} days ({time_since_insertion.days} days)."
                else:
                    report.status = "PASS"
                    report.status_extended = f"User {user.name} has logged in to the console in the past {maximum_expiration_days} days ({time_since_insertion.days} days)."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"User {user.name} does not have a console password or is unused."
                )

            # Append report
            findings.append(report)
        return findings
