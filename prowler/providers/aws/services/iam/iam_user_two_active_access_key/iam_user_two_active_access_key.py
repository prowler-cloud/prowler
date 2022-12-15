from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_two_active_access_key(Check):
    def execute(self) -> Check_Report_AWS:
        try:
            findings = []
            response = iam_client.credential_report
            for user in response:
                report = Check_Report_AWS(self.metadata())
                report.resource_id = user["user"]
                report.resource_arn = user["arn"]
                report.region = iam_client.region
                if (
                    user["access_key_1_active"] == "true"
                    and user["access_key_2_active"] == "true"
                ):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User {user['user']} has 2 active access keys."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"User {user['user']} has not 2 active access keys."
                    )
                findings.append(report)
        except Exception as error:
            logger.error(f"{error.__class__.__name__} -- {error}")
        finally:
            return findings
