from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_login_challenges_configured(Check):
    """Check that login challenges are configured correctly.

    This check verifies that the employee ID login challenge is disabled,
    as recommended by CIS. Note: CIS 4.1.4.1 also requires Post-SSO
    verification to be enabled, but that setting is not exposed by the
    Cloud Identity Policy API. This check only covers the employee ID
    challenge portion of the control.
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

            employee_id_enabled = security_client.policies.login_challenge_employee_id

            if employee_id_enabled is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Employee ID login challenge is disabled "
                    f"in domain {security_client.provider.identity.domain}. "
                    f"Note: Post-SSO verification status cannot be verified "
                    f"via the Policy API."
                )
            elif employee_id_enabled is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Employee ID login challenge uses Google's secure default "
                    f"configuration (disabled) "
                    f"in domain {security_client.provider.identity.domain}. "
                    f"Note: Post-SSO verification status cannot be verified "
                    f"via the Policy API."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Employee ID login challenge is enabled "
                    f"in domain {security_client.provider.identity.domain}. "
                    f"The employee ID challenge should be disabled per CIS "
                    f"recommendations. Note: Post-SSO verification status "
                    f"cannot be verified via the Policy API."
                )

            findings.append(report)

        return findings
