from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_group_has_users_check(Check):
    def execute(self):
        findings = []

        for group in iam_client.groups:
            report = Check_Report_AWS(self.metadata())
            report.region = "global"
            report.resource_id = group.name
            report.resource_arn = group.arn

            # Check if tags exist and handle if not
            if hasattr(group, 'tags'):
                report.resource_tags = group.tags
            else:
                report.resource_tags = []

            # Determine if group has users
            if group.users:
                report.status = "PASS"
                report.status_extended = f"IAM group {group.name} has users associated with it."
            else:
                report.status = "FAIL"
                report.status_extended = f"IAM group {group.name} has no users associated with it."

            findings.append(report)

        return findings
