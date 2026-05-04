from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_domain_spoofing_protection_enabled(Check):
    """Check that protection against domain spoofing based on similar domain names is enabled.

    This check verifies that Gmail is configured to take action on
    emails that appear to come from similar-looking domain names,
    helping prevent phishing via domain impersonation.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.domain_resource,
            )

            enabled = gmail_client.policies.detect_domain_name_spoofing
            consequence = gmail_client.policies.domain_spoofing_consequence

            if enabled is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against domain spoofing based on similar "
                    f"domain names is disabled in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"Enable the protection and configure a protective action."
                )
            elif consequence == "NO_ACTION":
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against domain spoofing based on similar "
                    f"domain names is set to take no action in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"A protective action should be configured."
                )
            elif consequence is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against domain spoofing based on similar "
                    f"domain names uses Google's secure default configuration "
                    f"(enabled) in domain "
                    f"{gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against domain spoofing based on similar "
                    f"domain names is enabled with consequence "
                    f"'{consequence}' in domain "
                    f"{gmail_client.provider.identity.domain}."
                )

            findings.append(report)

        return findings
