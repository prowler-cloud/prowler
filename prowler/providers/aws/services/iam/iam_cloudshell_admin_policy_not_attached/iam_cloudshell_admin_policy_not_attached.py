from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_cloudshell_admin_policy_not_attached(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.entities_attached_to_cloudshell_policy is not None:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_id = iam_client.audited_account
            report.resource_arn = f"arn:{iam_client.audited_partition}:iam::aws:policy/AWSCloudShellFullAccess"
            report.status = "PASS"
            report.status_extended = (
                "AWS CloudShellFullAccess policy is not attached to any IAM entity."
            )
            if iam_client.entities_attached_to_cloudshell_policy:
                report.status = "FAIL"
                report.status_extended = f"AWS CloudShellFullAccess policy attached to IAM entities: {', '.join(iam_client.entities_attached_to_cloudshell_policy)}."
            findings.append(report)
        return findings
