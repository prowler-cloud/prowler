from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_super_admin_recovery_disabled(Check):
    """Check that Super Admin account recovery is disabled.

    This check verifies that the domain-level policy prevents Super Admin
    users from recovering their account through self-service, reducing the
    risk of account takeover through the recovery flow.
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

            recovery_enabled = security_client.policies.super_admin_recovery_enabled

            if recovery_enabled is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Super Admin account recovery is disabled "
                    f"in domain {security_client.provider.identity.domain}."
                )
            elif recovery_enabled is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Super Admin account recovery uses Google's secure default "
                    f"configuration (disabled) "
                    f"in domain {security_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Super Admin account recovery is enabled "
                    f"in domain {security_client.provider.identity.domain}. "
                    f"Super Admin account recovery should be disabled to prevent "
                    f"account takeover through the recovery flow."
                )

            findings.append(report)

        return findings
