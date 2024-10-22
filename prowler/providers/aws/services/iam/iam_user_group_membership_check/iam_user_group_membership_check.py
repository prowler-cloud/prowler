from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_group_membership_check(Check):
    def execute(self):
        findings = []

        for user in iam_client.users:
            report = Check_Report_AWS(self.metadata())
            report.region = "global"
            report.resource_id = user.name
            report.resource_arn = user.arn
            report.resource_tags = user.tags

            # Check if the user belongs to any group
            if user.groups:
                report.status = "PASS"
                report.status_extended = f"IAM user {user.name} is in one or more groups."
            else:
                report.status = "FAIL"
                report.status_extended = f"IAM user {user.name} is not in any group."

            findings.append(report)

        return findings
