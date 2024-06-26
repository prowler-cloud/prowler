from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_support_role_created(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.entities_role_attached_to_support_policy is not None:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_id = "AWSSupportServiceRolePolicy"
            report.resource_arn = (
                "arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"
            )
            if iam_client.entities_role_attached_to_support_policy:
                report.status = "PASS"
                report.status_extended = f"Support policy attached to role {iam_client.entities_role_attached_to_support_policy[0]['RoleName']}."
            else:
                report.status = "FAIL"
                report.status_extended = "Support policy is not attached to any role."
            findings.append(report)
        return findings
