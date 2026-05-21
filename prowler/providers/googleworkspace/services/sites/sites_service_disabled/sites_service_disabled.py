from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.sites.sites_client import sites_client


class sites_service_disabled(Check):
    """Check that the Google Sites service is disabled for all users.

    This check verifies that the domain-level policy disables the Google Sites
    service, reducing the organization's attack surface by preventing users
    from creating internal or external websites.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if sites_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=sites_client.policies,
                resource_id="sitesPolicies",
                resource_name="Sites Policies",
                customer_id=sites_client.provider.identity.customer_id,
            )

            service_state = sites_client.policies.service_state

            if service_state == "DISABLED":
                report.status = "PASS"
                report.status_extended = (
                    f"Google Sites service is disabled "
                    f"in domain {sites_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if service_state is None:
                    report.status_extended = (
                        f"Google Sites service is not explicitly configured "
                        f"in domain {sites_client.provider.identity.domain}. "
                        f"The default is ON for everyone. Google Sites should be disabled."
                    )
                else:
                    report.status_extended = (
                        f"Google Sites service is enabled "
                        f"in domain {sites_client.provider.identity.domain}. "
                        f"Google Sites should be disabled."
                    )

            findings.append(report)

        return findings
