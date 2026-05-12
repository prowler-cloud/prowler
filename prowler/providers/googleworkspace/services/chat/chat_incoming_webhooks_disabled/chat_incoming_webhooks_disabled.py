from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.chat.chat_client import chat_client


class chat_incoming_webhooks_disabled(Check):
    """Check that incoming webhooks are disabled in Google Chat.

    This check verifies that the domain-level Chat policy prevents users
    from adding and using incoming webhooks, reducing the risk of
    unauthorized content being posted into Chat spaces.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if chat_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=chat_client.provider.domain_resource,
            )

            webhooks_enabled = chat_client.policies.enable_webhooks

            if webhooks_enabled is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Incoming webhooks are disabled "
                    f"in domain {chat_client.provider.identity.domain}."
                )
            elif webhooks_enabled is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Incoming webhooks use Google's secure default "
                    f"configuration (disabled) "
                    f"in domain {chat_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Incoming webhooks are enabled "
                    f"in domain {chat_client.provider.identity.domain}. "
                    f"Incoming webhooks should be disabled to prevent unauthorized content."
                )

            findings.append(report)

        return findings
