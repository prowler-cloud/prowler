from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_app_access_restricted(Check):
    """Check that application access to Google services is restricted.

    This check verifies that at least one Google service has API access
    restricted for third-party apps, indicating that the administrator
    has reviewed and configured API access controls. The CIS benchmark
    recommends restricting access to all applicable services, particularly
    high-risk scopes like Drive and Gmail. This check serves as a signal
    that API access controls have been configured rather than left at the
    unrestricted default.
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

            restricted = security_client.policies.google_services_restricted
            domain = security_client.provider.identity.domain

            if restricted is True:
                report.status = "PASS"
                report.status_extended = (
                    f"Application access to Google services is restricted "
                    f"in domain {domain}. At least one Google service has "
                    f"API access limited to trusted apps."
                )
            else:
                report.status = "FAIL"
                if restricted is None:
                    report.status_extended = (
                        f"Application access to Google services is not configured "
                        f"in domain {domain}. The default is unrestricted. "
                        f"API access should be restricted for all applicable "
                        f"Google services, particularly high-risk scopes."
                    )
                else:
                    report.status_extended = (
                        f"Application access to Google services is unrestricted "
                        f"in domain {domain}. "
                        f"API access should be restricted for all applicable "
                        f"Google services, particularly high-risk scopes."
                    )

            findings.append(report)

        return findings
