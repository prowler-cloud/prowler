from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_policy_attached_only_to_group_or_roles(Check):
    """Check if RAM policies are attached only to groups or roles, not directly to users."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for user in ram_client.users:
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=user)
            report.region = ram_client.region
            report.resource_id = user.name
            report.resource_arn = (
                f"acs:ram::{ram_client.audited_account}:user/{user.name}"
            )

            if user.attached_policies:
                report.status = "FAIL"
                policy_names = [policy.policy_name for policy in user.attached_policies]
                report.status_extended = (
                    f"RAM user {user.name} has {len(user.attached_policies)} "
                    f"policies directly attached: {', '.join(policy_names)}. "
                    f"Policies should be attached to groups or roles instead."
                )
                findings.append(report)
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"RAM user {user.name} has no policies directly attached."
                )
                findings.append(report)

        return findings
