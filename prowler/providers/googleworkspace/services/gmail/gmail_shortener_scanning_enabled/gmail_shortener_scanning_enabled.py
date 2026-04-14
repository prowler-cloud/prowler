from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_shortener_scanning_enabled(Check):
    """Check that identification of links behind shortened URLs is enabled.

    This check verifies that Gmail is configured to expand and scan
    shortened URLs to identify potentially malicious destinations
    hidden behind URL shortening services.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.identity,
                resource_name=gmail_client.provider.identity.domain,
                resource_id=gmail_client.provider.identity.customer_id,
                customer_id=gmail_client.provider.identity.customer_id,
                location="global",
            )

            scanning_enabled = gmail_client.policies.enable_shortener_scanning

            if scanning_enabled is True:
                report.status = "PASS"
                report.status_extended = (
                    f"Identification of links behind shortened URLs is enabled "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            elif scanning_enabled is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Identification of links behind shortened URLs uses Google's "
                    f"secure default configuration (enabled) "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Identification of links behind shortened URLs is disabled "
                    f"in domain {gmail_client.provider.identity.domain}. "
                    f"Shortened URL scanning should be enabled to detect hidden malicious links."
                )

            findings.append(report)

        return findings
