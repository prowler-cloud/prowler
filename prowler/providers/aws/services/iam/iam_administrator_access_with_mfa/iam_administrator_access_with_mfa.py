from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_administrator_access_with_mfa(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        response = iam_client.groups

        for group in response:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = group.name
            report.resource_arn = group.arn
            report.region = iam_client.region
            report.status = "PASS"
            report.status_extended = f"Group {group.name} has no policies."

            if group.attached_policies:
                report.status_extended = (
                    f"Group {group.name} provides non-administrative access."
                )
                for group_policy in group.attached_policies:
                    if (
                        group_policy["PolicyArn"]
                        == "arn:aws:iam::aws:policy/AdministratorAccess"
                    ):
                        # users in group are Administrators
                        if group.users:
                            for group_user in group.users:
                                for user in iam_client.credential_report:
                                    if (
                                        user["user"] == group_user.name
                                        and user["mfa_active"] == "false"
                                    ):
                                        report.status = "FAIL"
                                        report.status_extended = f"Group {group.name} provides administrator access to User {group_user.name} with MFA disabled."
                        else:
                            report.status_extended = f"Group {group.name} provides administrative access but does not have users."

            findings.append(report)

        return findings
