"""
Check: ram_no_admin_privileges

Ensures that RAM users do not have administrative privileges.
Following principle of least privilege, admin access should be granted only when necessary.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_no_admin_privileges(Check):
    """Check if RAM users have unnecessary administrative privileges"""

    def execute(self):
        """Execute the ram_no_admin_privileges check"""
        findings = []

        for user_arn, user in ram_client.users.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=user)
            report.account_uid = ram_client.account_id
            report.region = "global"
            report.resource_id = user.id
            report.resource_arn = user.arn

            # Check if user has AdministratorAccess policy
            has_admin = False
            admin_policies = []
            
            if user.attached_policies:
                for policy in user.attached_policies:
                    policy_name = policy.get("PolicyName", "")
                    if "Administrator" in policy_name or "FullAccess" in policy_name:
                        has_admin = True
                        admin_policies.append(policy_name)

            if not has_admin:
                report.status = "PASS"
                report.status_extended = f"RAM user {user.name} does not have administrative privileges."
            else:
                report.status = "FAIL"
                report.status_extended = f"RAM user {user.name} has administrative privileges via: {', '.join(admin_policies)}. Follow principle of least privilege."

            findings.append(report)

        return findings
