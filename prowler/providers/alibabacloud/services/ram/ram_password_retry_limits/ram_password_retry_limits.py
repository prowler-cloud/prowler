"""
Check: ram_password_retry_limits

Ensures that the RAM password policy has login retry limits configured.
This prevents brute-force attacks by locking accounts after failed login attempts.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_retry_limits(Check):
    """Check if the RAM password policy has appropriate login retry limits"""

    def execute(self):
        """Execute the ram_password_retry_limits check"""
        findings = []

        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=type('obj', (object,), {
            'id': 'password-policy',
            'name': 'RAM Password Policy',
            'arn': f"acs:ram::{ram_client.account_id}:password-policy",
            'region': 'global'
        })())

        report.account_uid = ram_client.account_id
        report.region = "global"
        report.resource_id = "password-policy"
        report.resource_arn = f"acs:ram::{ram_client.account_id}:password-policy"

        if ram_client.password_policy:
            max_attempts = ram_client.password_policy.max_login_attempts

            if 1 <= max_attempts <= 5:
                report.status = "PASS"
                report.status_extended = f"RAM password policy limits login attempts to {max_attempts} (meets the 1-5 requirement)."
            else:
                report.status = "FAIL"
                report.status_extended = f"RAM password policy allows {max_attempts} login attempts. Set maximum login attempts between 1 and 5 to prevent brute-force attacks."
        else:
            report.status = "FAIL"
            report.status_extended = "No RAM password policy is configured. Configure a password policy with login retry limits."

        findings.append(report)
        return findings
