from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_mail_delegation_disabled(Check):
    """Check that users cannot delegate access to their mailbox.

    This check verifies that the domain-level Gmail policy prevents users
    from delegating mailbox access to other users, ensuring only
    administrators can manage mailbox delegation.
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

            delegation_enabled = gmail_client.policies.enable_mail_delegation

            if delegation_enabled is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Mail delegation is disabled "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            elif delegation_enabled is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Mail delegation uses Google's secure default configuration "
                    f"(disabled) in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Mail delegation is enabled "
                    f"in domain {gmail_client.provider.identity.domain}. "
                    f"Users should not be able to delegate access to their mailbox."
                )

            findings.append(report)

        return findings
