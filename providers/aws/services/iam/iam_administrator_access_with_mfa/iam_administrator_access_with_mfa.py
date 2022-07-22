from lib.check.models import Check, Check_Report
from providers.aws.services.iam.iam_service import iam_client


class iam_administrator_access_with_mfa(Check):
    def execute(self) -> Check_Report:
        findings = []
        response = iam_client.groups

        if response:
            for group in response:
                report = Check_Report(self.metadata)
                report.resource_id = group.name
                report.resource_arn = group.arn
                report.region = "us-east-1"
                if group.attached_policies:
                    admin_policy = False
                    for group_policy in group.attached_policies:
                        if (
                            group_policy["PolicyArn"]
                            == "arn:aws:iam::aws:policy/AdministratorAccess"
                        ):
                            admin_policy = True
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
                                            findings.append(report)
                                        elif (
                                            user["user"] == group_user.name
                                            and user["mfa_active"] == "true"
                                        ):
                                            report.status = "PASS"
                                            report.status_extended = f"Group {group.name} provides administrator access to User {group_user.name} with MFA enabled."
                                            findings.append(report)
                            else:
                                report.status = "PASS"
                                report.status_extended = f"Group {group.name} provides administrative access but does not have users."
                                findings.append(report)
                    if not admin_policy:
                        report.status = "PASS"
                        report.status_extended = (
                            f"Group {group.name} provides non-administrative access."
                        )
                        findings.append(report)
                else:
                    report.status = "PASS"
                    report.status_extended = f"Group {group.name} has no policies."
                    findings.append(report)

        else:
            report = Check_Report(self.metadata)
            report.status = "PASS"
            report.status_extended = "There is no IAM groups."
            report.region = iam_client.region
            findings.append(report)

        return findings
