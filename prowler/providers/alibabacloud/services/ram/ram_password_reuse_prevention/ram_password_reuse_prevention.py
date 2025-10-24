"""
Check: ram_password_reuse_prevention

Ensures that the RAM password policy prevents password reuse.
Preventing password reuse helps ensure that old passwords, which may have been compromised, cannot be reused.

Risk Level: LOW
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_reuse_prevention(Check):
    """Check if the RAM password policy prevents password reuse"""

    def execute(self):
        """Execute the ram_password_reuse_prevention check"""
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
            reuse_prevention = ram_client.password_policy.password_reuse_prevention

            if reuse_prevention > 0:
                report.status = "PASS"
                report.status_extended = f"RAM password policy prevents reuse of the last {reuse_prevention} password(s)."
            else:
                report.status = "FAIL"
                report.status_extended = "RAM password policy does not prevent password reuse. Enable password reuse prevention to improve security."
        else:
            report.status = "FAIL"
            report.status_extended = "No RAM password policy is configured. Configure a password policy with password reuse prevention enabled."

        findings.append(report)
        return findings
