from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_pop_imap_access_disabled(Check):
    """Check that POP and IMAP access is disabled for all users.

    This check verifies that the domain-level Gmail policy disables both
    POP and IMAP access, preventing users from accessing email through
    legacy clients that may not support modern authentication.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.domain_resource,
            )

            pop_enabled = gmail_client.policies.enable_pop_access
            imap_enabled = gmail_client.policies.enable_imap_access

            if pop_enabled is False and imap_enabled is False:
                report.status = "PASS"
                report.status_extended = (
                    f"POP and IMAP access are both disabled "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                enabled_protocols = []
                not_configured = []

                if pop_enabled is True:
                    enabled_protocols.append("POP")
                elif pop_enabled is None:
                    not_configured.append("POP")

                if imap_enabled is True:
                    enabled_protocols.append("IMAP")
                elif imap_enabled is None:
                    not_configured.append("IMAP")

                details = []
                if enabled_protocols:
                    details.append(
                        f"{' and '.join(enabled_protocols)} access is enabled"
                    )
                if not_configured:
                    details.append(
                        f"{' and '.join(not_configured)} access is not explicitly configured"
                    )

                report.status_extended = (
                    f"{'; '.join(details)} "
                    f"in domain {gmail_client.provider.identity.domain}. "
                    f"Both POP and IMAP access should be disabled to prevent use of "
                    f"legacy email clients."
                )

            findings.append(report)

        return findings
