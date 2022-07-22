import datetime

from lib.check.models import Check, Check_Report
from providers.aws.services.iam.iam_service import iam_client

maximum_expiration_days = 90


class iam_disable_90_days_credentials(Check):
    def execute(self) -> Check_Report:
        findings = []
        response = iam_client.users

        if response:
            for user in response:
                report = Check_Report(self.metadata)
                report.region = "us-east-1"
                report.resource_id = user.name
                report.resource_arn = user.arn
                if user.password_last_used and user.password_last_used != "":
                    try:
                        time_since_insertion = (
                            datetime.datetime.now()
                            - datetime.datetime.strptime(
                                user.password_last_used, "%Y-%m-%dT%H:%M:%S+00:00"
                            )
                        )
                        if time_since_insertion.days > maximum_expiration_days:
                            report.status = "FAIL"
                            report.status_extended = f"User {user.name} has not logged into the console in the past 90 days."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"User {user.name} has logged into the console in the past 90 days."

                    except KeyError:
                        pass
                else:
                    report.status = "PASS"

                    report.status_extended = (
                        f"User {user.name} has not a console password or is unused."
                    )
                # Append report
                findings.append(report)
        else:
            report = Check_Report(self.metadata)
            report.status = "PASS"
            report.status_extended = "There is no IAM users."
            report.region = "us-east-1"
            findings.append(report)

        return findings
