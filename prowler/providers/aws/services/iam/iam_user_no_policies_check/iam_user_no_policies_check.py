from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_no_policies_check(Check):
    def execute(self):
        findings = []

        for user in iam_client.users:
            report = Check_Report_AWS(self.metadata())
            report.region = "global"
            report.resource_id = user.name
            report.resource_arn = user.arn
            report.resource_tags = user.tags

            # Check if the user has any attached or inline policies
            if user.attached_policies or user.inline_policies:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM user {user.name} has policies directly attached."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM user {user.name} has no policies directly attached."
                )

            findings.append(report)

        return findings
