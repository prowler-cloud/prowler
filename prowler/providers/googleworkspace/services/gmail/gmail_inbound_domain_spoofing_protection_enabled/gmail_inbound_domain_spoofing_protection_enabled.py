from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_inbound_domain_spoofing_protection_enabled(Check):
    """Check that protection against inbound emails spoofing your domain is enabled.

    This check verifies that Gmail is configured to take action on
    inbound emails that spoof the organization's own domain, helping
    prevent impersonation of internal senders.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.domain_resource,
            )

            enabled = gmail_client.policies.detect_inbound_domain_spoofing
            consequence = gmail_client.policies.inbound_domain_spoofing_consequence

            if enabled is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against inbound emails spoofing your domain "
                    f"is disabled in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"Enable the protection and configure a protective action."
                )
            elif consequence == "NO_ACTION":
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against inbound emails spoofing your domain "
                    f"is set to take no action in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"A protective action should be configured."
                )
            elif consequence is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against inbound emails spoofing your domain "
                    f"uses Google's secure default configuration (enabled) "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against inbound emails spoofing your domain "
                    f"is enabled with consequence '{consequence}' "
                    f"in domain {gmail_client.provider.identity.domain}."
                )

            findings.append(report)

        return findings
