from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import check_admin_access


class iam_inline_policy_no_administrative_privileges(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for policy in iam_client.policies:
            if policy.type == "Inline":
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_arn = policy.arn
                report.resource_id = f"{policy.entity}/{policy.name}"
                report.resource_tags = policy.tags
                report.status = "PASS"

                if "role" in report.resource_arn:
                    resource_type_str = "role"
                elif "group" in report.resource_arn:
                    resource_type_str = "group"
                elif "user" in report.resource_arn:
                    resource_type_str = "user"
                else:
                    resource_type_str = "resource"

                report.status_extended = f"{policy.type} policy {policy.name} attached to {resource_type_str} {report.resource_arn} does not allow '*:*' administrative privileges."
                if policy.document:
                    if check_admin_access(policy.document):
                        report.status = "FAIL"
                        report.status_extended = f"{policy.type} policy {policy.name} attached to {resource_type_str} {report.resource_arn} allows '*:*' administrative privileges."
                findings.append(report)
        return findings
