from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_policy_cloudshell_admin_not_attached(Check):
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
            if (
                iam_client.entities_attached_to_cloudshell_policy["Users"]
                or iam_client.entities_attached_to_cloudshell_policy["Groups"]
                or iam_client.entities_attached_to_cloudshell_policy["Roles"]
            ):
                report.status = "FAIL"
                if (
                    len(iam_client.entities_attached_to_cloudshell_policy["Users"]) > 0
                    and len(iam_client.entities_attached_to_cloudshell_policy["Groups"])
                    > 0
                    and len(iam_client.entities_attached_to_cloudshell_policy["Roles"])
                    > 0
                ):
                    report.status_extended = f"AWS CloudShellFullAccess policy attached to IAM Users: {', '.join(iam_client.entities_attached_to_cloudshell_policy['Users'])}, Groups {', '.join(iam_client.entities_attached_to_cloudshell_policy['Groups'])}, Roles {', '.join(iam_client.entities_attached_to_cloudshell_policy['Roles'])}."
                elif (
                    len(iam_client.entities_attached_to_cloudshell_policy["Users"]) > 0
                    and len(iam_client.entities_attached_to_cloudshell_policy["Groups"])
                    > 0
                ):
                    report.status_extended = f"AWS CloudShellFullAccess policy attached to IAM Users: {', '.join(iam_client.entities_attached_to_cloudshell_policy['Users'])}, Groups {', '.join(iam_client.entities_attached_to_cloudshell_policy['Groups'])}."
                elif (
                    len(iam_client.entities_attached_to_cloudshell_policy["Users"]) > 0
                    and len(iam_client.entities_attached_to_cloudshell_policy["Roles"])
                    > 0
                ):
                    report.status_extended = f"AWS CloudShellFullAccess policy attached to IAM Users: {', '.join(iam_client.entities_attached_to_cloudshell_policy['Users'])}, Roles {', '.join(iam_client.entities_attached_to_cloudshell_policy['Roles'])}."
                elif (
                    len(iam_client.entities_attached_to_cloudshell_policy["Groups"]) > 0
                    and len(iam_client.entities_attached_to_cloudshell_policy["Roles"])
                    > 0
                ):
                    report.status_extended = f"AWS CloudShellFullAccess policy attached to IAM Groups: {', '.join(iam_client.entities_attached_to_cloudshell_policy['Groups'])}, Roles {', '.join(iam_client.entities_attached_to_cloudshell_policy['Roles'])}."
                elif (
                    len(iam_client.entities_attached_to_cloudshell_policy["Users"]) > 0
                ):
                    report.status_extended = f"AWS CloudShellFullAccess policy attached to IAM Users: {', '.join(iam_client.entities_attached_to_cloudshell_policy['Users'])}."
                elif (
                    len(iam_client.entities_attached_to_cloudshell_policy["Groups"]) > 0
                ):
                    report.status_extended = f"AWS CloudShellFullAccess policy attached to IAM Groups: {', '.join(iam_client.entities_attached_to_cloudshell_policy['Groups'])}."
                elif (
                    len(iam_client.entities_attached_to_cloudshell_policy["Roles"]) > 0
                ):
                    report.status_extended = f"AWS CloudShellFullAccess policy attached to IAM Roles: {', '.join(iam_client.entities_attached_to_cloudshell_policy['Roles'])}."
            findings.append(report)
        return findings
