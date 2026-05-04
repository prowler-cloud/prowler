from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_unauthenticated_email_protection_enabled(Check):
    """Check that protection against any unauthenticated emails is enabled.

    This check verifies that Gmail is configured to take action on
    emails that are not authenticated via SPF or DKIM, helping prevent
    delivery of spoofed or forged messages.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.domain_resource,
            )

            enabled = gmail_client.policies.detect_unauthenticated_emails
            consequence = gmail_client.policies.unauthenticated_email_consequence

            if enabled is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against unauthenticated emails is disabled "
                    f"in domain {gmail_client.provider.identity.domain}. "
                    f"Enable the protection and configure a protective action."
                )
            elif enabled is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against unauthenticated emails is not "
                    f"configured and uses Google's insecure default "
                    f"(disabled) in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"Enable the protection and configure a protective action."
                )
            elif consequence == "NO_ACTION":
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against unauthenticated emails is set to "
                    f"take no action in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"A protective action should be configured."
                )
            elif consequence is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against unauthenticated emails is enabled "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against unauthenticated emails is enabled "
                    f"with consequence '{consequence}' in domain "
                    f"{gmail_client.provider.identity.domain}."
                )

            findings.append(report)

        return findings
