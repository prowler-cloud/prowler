from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_policy_cloudshell_admin_not_attached(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.entities_attached_to_cloudshell_policy:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_id = iam_client.audited_account
            report.resource_arn = f"arn:{iam_client.audited_partition}:iam::aws:policy/AWSCloudShellFullAccess"
            entities = iam_client.entities_attached_to_cloudshell_policy

            if entities["Users"] or entities["Groups"] or entities["Roles"]:
                report.status = "FAIL"
                attached_entities = [
                    (key, ", ".join(entities[key]))
                    for key in ["Users", "Groups", "Roles"]
                    if entities[key]
                ]
                entity_strings = [
                    f"{entity[0]}: {entity[1]}" for entity in attached_entities
                ]
                report.status_extended = f"AWS CloudShellFullAccess policy attached to IAM {', '.join(entity_strings)}."
            else:
                report.status = "PASS"
                report.status_extended = (
                    "AWS CloudShellFullAccess policy is not attached to any IAM entity."
                )

            findings.append(report)

        return findings
