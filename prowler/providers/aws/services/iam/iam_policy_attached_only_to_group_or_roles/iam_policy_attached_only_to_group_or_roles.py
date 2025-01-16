from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_policy_attached_only_to_group_or_roles(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.users:
            for user in iam_client.users:
                if user.attached_policies or user.inline_policies:
                    if user.attached_policies:
                        for policy in user.attached_policies:
                            report = Check_Report_AWS(
                                metadata=self.metadata(), resource_metadata=user
                            )
                            report.region = iam_client.region
                            report.status = "FAIL"
                            report.status_extended = f"User {user.name} has the policy {policy['PolicyName']} attached."
                            report.resource_id = f"{user.name}/{policy['PolicyName']}"
                            findings.append(report)
                    if user.inline_policies:
                        for policy in user.inline_policies:
                            report = Check_Report_AWS(
                                metadata=self.metadata(), resource_metadata=user
                            )
                            report.region = iam_client.region
                            report.status = "FAIL"
                            report.status_extended = f"User {user.name} has the inline policy {policy} attached."
                            report.resource_id = f"{user.name}/{policy}"
                            findings.append(report)

                else:
                    report = Check_Report_AWS(
                        metadata=self.metadata(), resource_metadata=user
                    )
                    report.region = iam_client.region
                    report.status = "PASS"
                    report.status_extended = (
                        f"User {user.name} has no inline or attached policies."
                    )
                    findings.append(report)
        return findings
