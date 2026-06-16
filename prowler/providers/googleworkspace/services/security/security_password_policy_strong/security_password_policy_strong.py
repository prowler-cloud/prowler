from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_password_policy_strong(Check):
    """Check that password policy is configured for enhanced security.

    This check verifies that the domain-level password policy meets CIS
    requirements: minimum length of 14 characters, strong passwords enforced,
    password reuse disallowed, enforcement at next sign-in, and password
    expiration configured.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if security_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=security_client.policies,
                resource_id="securityPolicies",
                resource_name="Security Policies",
                customer_id=security_client.provider.identity.customer_id,
            )

            policies = security_client.policies
            domain = security_client.provider.identity.domain
            issues = []

            min_length = policies.password_minimum_length
            if min_length is None or min_length < 14:
                issues.append(
                    "minimum length is not configured (requires 14+)"
                    if min_length is None
                    else f"minimum length is {min_length} (requires 14+)"
                )

            if policies.password_allowed_strength != "STRONG":
                issues.append(
                    "password strength is not configured (requires STRONG)"
                    if policies.password_allowed_strength is None
                    else f"password strength is {policies.password_allowed_strength} (requires STRONG)"
                )

            if policies.password_allow_reuse is True:
                issues.append("password reuse is allowed")

            if policies.password_enforce_at_login is not True:
                issues.append("password policy is not enforced at next sign-in")

            expiration = policies.password_expiration_duration
            if expiration is None or expiration == "0s":
                issues.append("password expiration is not configured")

            if not issues:
                report.status = "PASS"
                report.status_extended = (
                    f"Password policy meets CIS requirements "
                    f"in domain {domain}: minimum length {min_length}, "
                    f"strong passwords enforced, reuse disallowed, "
                    f"enforced at next sign-in, expiration configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Password policy does not meet CIS requirements "
                    f"in domain {domain}: {'; '.join(issues)}."
                )

            findings.append(report)

        return findings
