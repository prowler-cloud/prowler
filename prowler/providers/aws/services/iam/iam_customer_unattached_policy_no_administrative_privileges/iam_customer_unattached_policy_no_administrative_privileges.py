from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import check_admin_access


class iam_customer_unattached_policy_no_administrative_privileges(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for policy in iam_client.policies:
            # Check only for cutomer unattached policies
            if not policy.attached and policy.type == "Custom":
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource_metadata=policy
                )
                report.region = iam_client.region
                report.status = "PASS"
                report.status_extended = f"{policy.type} policy {policy.name} is unattached and does not allow '*:*' administrative privileges."
                if policy.document:
                    if check_admin_access(policy.document):
                        report.status = "FAIL"
                        report.status_extended = f"{policy.type} policy {policy.name} is unattached and allows '*:*' administrative privileges."
                findings.append(report)
        return findings
