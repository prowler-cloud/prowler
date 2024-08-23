from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_administrator_access_policy(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        for user in iam_client.users:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_arn = user.arn
            report.resource_id = user.name
            report.resource_tags = user.tags
            report.status = "PASS"
            report.status_extended = (
                f"IAM User {user.name} does not have AdministratorAccess policy."
            )
            for policy in user.attached_policies:
                if policy["PolicyName"] == "AdministratorAccess":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"IAM User {user.name} has AdministratorAccess policy attached."
                    )
                    break

            findings.append(report)

        return findings
