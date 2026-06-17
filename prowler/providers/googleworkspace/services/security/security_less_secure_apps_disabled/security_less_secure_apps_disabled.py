from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_less_secure_apps_disabled(Check):
    """Check that less secure app access is disabled.

    This check verifies that the domain-level policy prevents users from
    allowing access to apps that use less secure sign-in technology,
    reducing the risk of credential compromise.
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

            less_secure_allowed = security_client.policies.less_secure_apps_allowed

            if less_secure_allowed is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Less secure app access is disabled "
                    f"in domain {security_client.provider.identity.domain}."
                )
            elif less_secure_allowed is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Less secure app access uses Google's secure default "
                    f"configuration (disabled) "
                    f"in domain {security_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Less secure app access is enabled "
                    f"in domain {security_client.provider.identity.domain}. "
                    f"Less secure app access should be disabled to prevent "
                    f"credential compromise through apps that do not use modern "
                    f"security standards."
                )

            findings.append(report)

        return findings
