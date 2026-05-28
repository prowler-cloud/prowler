from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_2sv_hardware_keys_admins(Check):
    """Check that 2SV enforcement requires hardware security keys.

    This check verifies that the domain-level 2-Step Verification enforcement
    factor is set to security keys only, providing the strongest protection
    against phishing attacks. Note: the Cloud Identity Policy API returns
    domain-wide policies — it cannot verify enforcement for admin roles
    specifically. This check evaluates the customer-level policy which
    applies to all users including administrators.
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

            factor_set = security_client.policies.two_sv_allowed_factor_set

            if factor_set == "PASSKEY_ONLY":
                report.status = "PASS"
                report.status_extended = (
                    f"2-Step Verification enforcement requires security keys only "
                    f"in domain {security_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if factor_set is None:
                    report.status_extended = (
                        f"2-Step Verification enforcement factor is not configured "
                        f"in domain {security_client.provider.identity.domain}. "
                        f"The default allows all methods including SMS and phone call. "
                        f"Security keys should be required for administrative accounts. "
                        f"Note: this check evaluates the domain-wide policy, the Policy "
                        f"API does not expose role-specific 2SV enforcement."
                    )
                else:
                    report.status_extended = (
                        f"2-Step Verification enforcement factor is set to "
                        f"{factor_set} "
                        f"in domain {security_client.provider.identity.domain}. "
                        f"Only security keys (PASSKEY_ONLY) should be allowed for "
                        f"administrative accounts. "
                        f"Note: this check evaluates the domain-wide policy, the Policy "
                        f"API does not expose role-specific 2SV enforcement."
                    )

            findings.append(report)

        return findings
