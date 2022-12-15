from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_policy_attached_only_to_group_or_roles(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.users:
            for user in iam_client.users:
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_id = user.name
                report.resource_arn = user.arn
                if user.attached_policies or user.inline_policies:
                    if user.attached_policies:
                        for policy in user.attached_policies:
                            report = Check_Report_AWS(self.metadata())
                            report.region = iam_client.region
                            report.status = "FAIL"
                            report.status_extended = f"User {user.name} has attached the following policy {policy['PolicyName']}"
                            report.resource_id = user.name
                            findings.append(report)
                    if user.inline_policies:
                        for policy in user.inline_policies:
                            report = Check_Report_AWS(self.metadata())
                            report.region = iam_client.region
                            report.status = "FAIL"
                            report.status_extended = f"User {user.name} has the following inline policy {policy}"
                            report.resource_id = user.name
                            findings.append(report)

                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"User {user.name} has no inline or attached policies"
                    )
                    findings.append(report)
        return findings
