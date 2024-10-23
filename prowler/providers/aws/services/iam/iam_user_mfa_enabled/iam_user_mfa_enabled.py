from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_mfa_enabled(Check):
    def execute(self):
        findings = []

        for user in iam_client.users:
            report = Check_Report_AWS(self.metadata())
            report.region = "global"
            report.resource_id = user.name
            report.resource_arn = user.arn
            report.resource_tags = user.tags

            if user.mfa_devices:
                report.status = "PASS"
                report.status_extended = f"IAM user {user.name} has MFA enabled."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM user {user.name} does not have MFA enabled."
                )

            findings.append(report)

        return findings
