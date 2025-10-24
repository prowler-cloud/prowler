"""
Check: ram_root_access_keys_absent

Ensures that the root account does not have any active access keys.
The root account has unrestricted access to all resources. Using access keys for the root account
increases the risk of credential exposure.

Risk Level: CRITICAL
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_root_access_keys_absent(Check):
    """Check if the root account has any active access keys"""

    def execute(self):
        """Execute the ram_root_access_keys_absent check"""
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

        if not ram_client.root_has_access_keys:
            report.status = "PASS"
            report.status_extended = "Root account does not have any active access keys."
        else:
            report.status = "FAIL"
            report.status_extended = "Root account has active access keys. Remove all access keys from the root account and use RAM users instead."

        findings.append(report)
        return findings
