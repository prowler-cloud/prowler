from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_user_recovery_enabled(Check):
    """Check that user account recovery is enabled.

    This check verifies that the domain-level policy allows non-Super Admin
    users to recover their accounts through self-service, reducing helpdesk
    burden while maintaining access to their accounts.
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

            recovery_enabled = security_client.policies.user_recovery_enabled

            if recovery_enabled is True:
                report.status = "PASS"
                report.status_extended = (
                    f"User account recovery is enabled "
                    f"in domain {security_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if recovery_enabled is None:
                    report.status_extended = (
                        f"User account recovery is not explicitly configured "
                        f"in domain {security_client.provider.identity.domain}. "
                        f"The default is disabled. User account recovery should be "
                        f"enabled to reduce helpdesk burden."
                    )
                else:
                    report.status_extended = (
                        f"User account recovery is disabled "
                        f"in domain {security_client.provider.identity.domain}. "
                        f"User account recovery should be enabled to reduce "
                        f"helpdesk burden."
                    )

            findings.append(report)

        return findings
