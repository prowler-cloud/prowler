from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_group_administrator_access_policy(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        for group in iam_client.groups:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_arn = group.arn
            report.resource_id = group.name
            report.status = "PASS"
            report.status_extended = (
                f"IAM Group {group.name} does not have AdministratorAccess policy."
            )
            for policy in group.attached_policies:
                if policy["PolicyName"] == "AdministratorAccess":
                    report.status = "FAIL"
                    report.status_extended = f"IAM Group {group.name} has AdministratorAccess policy attached."
                    break

            findings.append(report)

        return findings
