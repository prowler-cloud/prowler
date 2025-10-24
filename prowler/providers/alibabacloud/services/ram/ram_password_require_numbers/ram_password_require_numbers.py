"""
Check: ram_password_require_numbers

Ensures that the RAM password policy requires at least one number.
This increases password complexity and makes them more resistant to attacks.

Risk Level: LOW
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_require_numbers(Check):
    """Check if the RAM password policy requires at least one number"""

    def execute(self):
        """Execute the ram_password_require_numbers check"""
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

        if ram_client.password_policy and ram_client.password_policy.require_numbers:
            report.status = "PASS"
            report.status_extended = "RAM password policy requires at least one number."
        else:
            report.status = "FAIL"
            report.status_extended = "RAM password policy does not require numbers. Enable the number requirement to increase password complexity."

        findings.append(report)
        return findings
