from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.marketplace.marketplace_client import (
    marketplace_client,
)


class marketplace_apps_access_restricted(Check):
    """Check that Google Workspace Marketplace app installation is restricted.

    This check verifies that the domain-level Marketplace policy restricts
    which apps users can install, preventing unvetted third-party applications
    from accessing organizational data.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if marketplace_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=marketplace_client.policies,
                resource_id="marketplacePolicies",
                resource_name="Marketplace Policies",
                customer_id=marketplace_client.provider.identity.customer_id,
            )

            access_level = marketplace_client.policies.access_level

            if access_level == "ALLOW_LISTED_APPS":
                report.status = "PASS"
                report.status_extended = (
                    f"Marketplace app installation is restricted to admin-approved apps "
                    f"in domain {marketplace_client.provider.identity.domain}."
                )
            elif access_level == "ALLOW_NONE":
                report.status = "PASS"
                report.status_extended = (
                    f"Marketplace app installation is fully blocked "
                    f"in domain {marketplace_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if access_level is None:
                    report.status_extended = (
                        f"Marketplace app access is not explicitly configured "
                        f"in domain {marketplace_client.provider.identity.domain}. "
                        f"The default allows all apps. "
                        f"App installation should be restricted to approved apps only."
                    )
                else:
                    report.status_extended = (
                        f"Marketplace allows users to install any app "
                        f"in domain {marketplace_client.provider.identity.domain}. "
                        f"App installation should be restricted to approved apps only."
                    )

            findings.append(report)

        return findings
