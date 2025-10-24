"""
Check: ram_root_mfa_enabled

Ensures that multi-factor authentication (MFA) is enabled for the root account.
The root account has unrestricted access to all resources in the Alibaba Cloud account.
MFA adds an extra layer of protection on top of the username and password.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_root_mfa_enabled(Check):
    """Check if MFA is enabled for the root account"""

    def execute(self):
        """Execute the ram_root_mfa_enabled check"""
        findings = []

        # Create a report for the root account
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=type('obj', (object,), {
            'id': 'root-account',
            'name': 'Root Account',
            'arn': f"acs:ram::{ram_client.account_id}:root",
            'region': 'global'
        })())

        report.account_uid = ram_client.account_id
        report.region = "global"
        report.resource_id = "root-account"
        report.resource_arn = f"acs:ram::{ram_client.account_id}:root"

        if ram_client.root_mfa_enabled:
            report.status = "PASS"
            report.status_extended = "Root account has MFA enabled."
        else:
            report.status = "FAIL"
            report.status_extended = "Root account does not have MFA enabled. Enable MFA for the root account to add an extra layer of security."

        findings.append(report)
        return findings
