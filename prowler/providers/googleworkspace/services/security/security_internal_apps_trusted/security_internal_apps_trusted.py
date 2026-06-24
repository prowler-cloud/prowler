from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_internal_apps_trusted(Check):
    """Check that internal apps can access Google Workspace APIs.

    This check verifies that the domain-level policy trusts internal
    domain-owned apps, allowing them to access restricted Google Workspace
    APIs without requiring individual trust configuration.
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

            trust_internal = security_client.policies.trust_internal_apps

            if trust_internal is True:
                report.status = "PASS"
                report.status_extended = (
                    f"Internal domain-owned apps are trusted to access "
                    f"Google Workspace APIs "
                    f"in domain {security_client.provider.identity.domain}."
                )
            elif trust_internal is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Internal domain-owned apps use Google's secure default "
                    f"configuration (trusted) "
                    f"in domain {security_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Internal domain-owned apps are not trusted to access "
                    f"Google Workspace APIs "
                    f"in domain {security_client.provider.identity.domain}. "
                    f"Internal apps should be trusted to access restricted APIs."
                )

            findings.append(report)

        return findings
