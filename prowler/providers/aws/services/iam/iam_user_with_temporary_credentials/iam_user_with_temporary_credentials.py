from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_with_temporary_credentials(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for (
            user_data,
            last_accessed_services,
        ) in iam_client.user_temporary_credentials_usage.items():
            user_name = user_data[0]
            user_arn = user_data[1]

            report = Check_Report_AWS(self.metadata())
            report.resource_id = user_name
            report.resource_arn = user_arn
            report.region = iam_client.region
            # Search user in iam_client.users to get tags
            for iam_user in iam_client.users:
                if iam_user.arn == user_arn:
                    report.resource_tags = iam_user.tags
                    break

            report.status = "PASS"
            report.status_extended = f"User {user_name} doesn't have long lived credentials with access to other services than IAM or STS."

            if last_accessed_services:
                report.status = "FAIL"
                report.status_extended = f"User {user_name} has long lived credentials with access to other services than IAM or STS."

            findings.append(report)

        return findings
