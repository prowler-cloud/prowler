"""
Check: ram_password_minimum_length

Ensures that the RAM password policy requires a minimum length of at least 14 characters.
Longer passwords are generally more secure as they are harder to crack through brute-force attacks.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.lib.check.check_utils import (
    GenericAlibabaCloudResource,
)
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_minimum_length(Check):
    """Check if the RAM password policy requires a minimum length of at least 14 characters"""

    def execute(self):
        """Execute the ram_password_minimum_length check"""
        findings = []

        # Create a report for the password policy
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
            minimum_length = ram_client.password_policy.minimum_length

            if minimum_length >= 14:
                report.status = "PASS"
                report.status_extended = f"RAM password policy requires a minimum length of {minimum_length} characters (meets the 14+ character requirement)."
            else:
                report.status = "FAIL"
                report.status_extended = f"RAM password policy requires a minimum length of only {minimum_length} characters. Increase the minimum password length to at least 14 characters."
        else:
            report.status = "FAIL"
            report.status_extended = "No RAM password policy is configured. Configure a password policy with a minimum length of at least 14 characters."

        findings.append(report)
        return findings
