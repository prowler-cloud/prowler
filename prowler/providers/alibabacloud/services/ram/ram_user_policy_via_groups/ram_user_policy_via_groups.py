"""
Check: ram_user_policy_via_groups

Ensures that RAM users receive permissions only through group membership, not through directly attached policies.
Using groups makes permission management easier and more consistent across users with similar roles.

Risk Level: LOW
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_user_policy_via_groups(Check):
    """Check if RAM users receive permissions through groups rather than direct policy attachment"""

    def execute(self):
        """Execute the ram_user_policy_via_groups check"""
        findings = []

        for user_arn, user in ram_client.users.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=user)
            report.account_uid = ram_client.account_id
            report.region = "global"
            report.resource_id = user.id
            report.resource_arn = user.arn

            # Check if user has directly attached policies
            if user.attached_policies and len(user.attached_policies) > 0:
                policy_names = [p.get("PolicyName", "Unknown") for p in user.attached_policies]
                report.status = "FAIL"
                report.status_extended = f"RAM user {user.name} has {len(user.attached_policies)} directly attached policy/policies: {', '.join(policy_names)}. Remove direct policy attachments and use group membership instead."
            else:
                report.status = "PASS"
                report.status_extended = f"RAM user {user.name} does not have any directly attached policies (uses group-based permissions)."

            findings.append(report)

        return findings
