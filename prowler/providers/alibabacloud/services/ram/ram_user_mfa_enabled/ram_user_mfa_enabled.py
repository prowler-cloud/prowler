"""
Check: ram_user_mfa_enabled

Ensures that multi-factor authentication (MFA) is enabled for all RAM users with console access.
MFA adds an extra layer of security by requiring users to provide a unique authentication code
from an approved authentication device in addition to their username and password.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_user_mfa_enabled(Check):
    """Check if MFA is enabled for all RAM users with console access"""

    def execute(self):
        """Execute the ram_user_mfa_enabled check"""
        findings = []

        for user_arn, user in ram_client.users.items():
            # Only check users with console login enabled
            if user.console_login_enabled:
                report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=user)
                report.account_uid = ram_client.account_id
                report.region = "global"
                report.resource_id = user.id
                report.resource_arn = user.arn

                if user.mfa_enabled:
                    report.status = "PASS"
                    report.status_extended = f"RAM user {user.name} has MFA enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RAM user {user.name} has console access but does not have MFA enabled. Enable MFA to add an extra layer of security."

                findings.append(report)

        return findings
