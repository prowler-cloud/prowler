from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_no_inline_policy_check(Check):
    def execute(self):
        findings = []

        # Check users
        for user in iam_client.users:
            report = Check_Report_AWS(self.metadata())
            report.region = "global"
            report.resource_id = user.name
            report.resource_arn = user.arn
            report.resource_tags = user.tags if hasattr(user, "tags") else []

            if user.inline_policies:
                report.status = "FAIL"
                report.status_extended = f"IAM user {user.name} has inline policies."
            else:
                report.status = "PASS"
                report.status_extended = f"IAM user {user.name} has no inline policies."

            findings.append(report)

        # Check groups
        for group in iam_client.groups:
            report = Check_Report_AWS(self.metadata())
            report.region = "global"
            report.resource_id = group.name
            report.resource_arn = group.arn
            report.resource_tags = group.tags if hasattr(group, "tags") else []

            if group.inline_policies:
                report.status = "FAIL"
                report.status_extended = f"IAM group {group.name} has inline policies."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM group {group.name} has no inline policies."
                )

            findings.append(report)

        # Check roles
        for role in iam_client.roles:
            report = Check_Report_AWS(self.metadata())
            report.region = "global"
            report.resource_id = role.name
            report.resource_arn = role.arn
            report.resource_tags = role.tags if hasattr(role, "tags") else []

            if role.inline_policies:
                report.status = "FAIL"
                report.status_extended = f"IAM role {role.name} has inline policies."
            else:
                report.status = "PASS"
                report.status_extended = f"IAM role {role.name} has no inline policies."

            findings.append(report)

        return findings
