from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_role_administratoraccess_policy(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.roles:
            for role in iam_client.roles:
                if (
                    not role.is_service_role
                ):  # Avoid service roles since they cannot be modified by the user
                    report = Check_Report_AWS(self.metadata())
                    report.region = iam_client.region
                    report.resource_arn = role.arn
                    report.resource_id = role.name
                    report.resource_tags = role.tags
                    report.status = "PASS"
                    report.status_extended = f"IAM Role {role.name} does not have AdministratorAccess policy."
                    for policy in role.attached_policies:
                        if policy["PolicyName"] == "AdministratorAccess":
                            report.status_extended = f"IAM Role {role.name} has AdministratorAccess policy attached."
                            report.status = "FAIL"

                    findings.append(report)

        return findings
