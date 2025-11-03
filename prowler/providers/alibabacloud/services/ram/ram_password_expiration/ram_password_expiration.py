"""
Check: ram_password_expiration

Ensures that the RAM password policy requires password expiration within 90 days or less.
Regular password rotation reduces the window of opportunity for compromised credentials to be exploited.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.lib.check.check_utils import (
    GenericAlibabaCloudResource,
)
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_expiration(Check):
    """Check if the RAM password policy requires password expiration within 90 days"""

    def execute(self):
        """Execute the ram_password_expiration check"""
        findings = []

        resource = GenericAlibabaCloudResource(
            id="password-policy",
            name="RAM Password Policy",
            arn=f"acs:ram::{ram_client.account_id}:password-policy",
            region="global",
        )
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=resource)

        report.account_uid = ram_client.account_id
        report.region = "global"
        report.resource_id = "password-policy"
        report.resource_arn = f"acs:ram::{ram_client.account_id}:password-policy"

        if ram_client.password_policy:
            max_age = ram_client.password_policy.max_password_age

            if 0 < max_age <= 90:
                report.status = "PASS"
                report.status_extended = f"RAM password policy requires passwords to expire within {max_age} days (meets the 90-day requirement)."
            elif max_age == 0:
                report.status = "FAIL"
                report.status_extended = "RAM password policy does not require password expiration. Set maximum password age to 90 days or less."
            else:
                report.status = "FAIL"
                report.status_extended = f"RAM password policy allows passwords to remain valid for {max_age} days. Reduce the maximum password age to 90 days or less."
        else:
            report.status = "FAIL"
            report.status_extended = "No RAM password policy is configured. Configure a password policy with a maximum password age of 90 days or less."

        findings.append(report)
        return findings
