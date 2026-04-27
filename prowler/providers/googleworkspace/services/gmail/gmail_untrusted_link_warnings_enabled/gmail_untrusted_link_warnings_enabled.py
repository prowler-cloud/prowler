from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_untrusted_link_warnings_enabled(Check):
    """Check that warning prompts for clicks on untrusted domain links are enabled.

    This check verifies that Gmail is configured to show warning prompts
    when users click on links to domains that are not trusted, helping
    prevent users from navigating to malicious sites.
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

            warnings_enabled = (
                gmail_client.policies.enable_aggressive_warnings_on_untrusted_links
            )

            if warnings_enabled is True:
                report.status = "PASS"
                report.status_extended = (
                    f"Warning prompts for clicks on untrusted domain links are enabled "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            elif warnings_enabled is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Warning prompts for clicks on untrusted domain links uses Google's "
                    f"secure default configuration (enabled) "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Warning prompts for clicks on untrusted domain links are disabled "
                    f"in domain {gmail_client.provider.identity.domain}. "
                    f"Untrusted link warnings should be enabled to protect users."
                )

            findings.append(report)

        return findings
