from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_support_role_created(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.entities_role_attached_to_support_policy is not None:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_id = iam_client.audited_account
            report.resource_arn = (
                f"arn:{iam_client.audited_partition}:iam::aws:policy/AWSSupportAccess"
            )
            if iam_client.entities_role_attached_to_support_policy:
                report.status = "PASS"
                report.status_extended = f"AWS Support Access policy attached to role {iam_client.entities_role_attached_to_support_policy[0]['RoleName']}."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "AWS Support Access policy is not attached to any role."
                )
            findings.append(report)
        return findings
