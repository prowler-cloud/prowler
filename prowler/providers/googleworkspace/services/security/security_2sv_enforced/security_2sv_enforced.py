from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_2sv_enforced(Check):
    """Check that 2-Step Verification is enforced for all users.

    This check verifies that the domain-level policy enforces 2-Step
    Verification (Multi-Factor Authentication) for all users, reducing
    the risk of account compromise through stolen credentials.
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

            enforced_from = security_client.policies.two_sv_enforced_from

            if enforced_from:
                report.status = "PASS"
                report.status_extended = (
                    f"2-Step Verification enforcement is active "
                    f"(enforced from {enforced_from}) "
                    f"in domain {security_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if enforced_from is None:
                    report.status_extended = (
                        f"2-Step Verification enforcement is not configured "
                        f"in domain {security_client.provider.identity.domain}. "
                        f"The default is OFF. 2-Step Verification should be "
                        f"enforced for all users."
                    )
                else:
                    report.status_extended = (
                        f"2-Step Verification enforcement is set to OFF "
                        f"in domain {security_client.provider.identity.domain}. "
                        f"2-Step Verification should be enforced for all users."
                    )

            findings.append(report)

        return findings
