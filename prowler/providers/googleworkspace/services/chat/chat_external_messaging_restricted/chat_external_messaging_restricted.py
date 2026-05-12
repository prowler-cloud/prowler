from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.chat.chat_client import chat_client


class chat_external_messaging_restricted(Check):
    """Check that external Chat messaging is restricted to allowed domains.

    This check verifies that external Chat messaging is either disabled
    entirely or restricted to allowlisted domains only, preventing
    unrestricted communication with external users.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if chat_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=chat_client.provider.domain_resource,
            )

            allow_external = chat_client.policies.allow_external_chat
            restriction = chat_client.policies.external_chat_restriction

            if allow_external is False:
                report.status = "PASS"
                report.status_extended = (
                    f"External Chat messaging is disabled "
                    f"in domain {chat_client.provider.identity.domain}."
                )
            elif allow_external is None and restriction is None:
                report.status = "PASS"
                report.status_extended = (
                    f"External Chat messaging uses Google's secure default "
                    f"configuration (disabled) "
                    f"in domain {chat_client.provider.identity.domain}."
                )
            elif restriction == "TRUSTED_DOMAINS":
                report.status = "PASS"
                report.status_extended = (
                    f"External Chat messaging is restricted to allowed domains "
                    f"in domain {chat_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"External Chat messaging is not restricted to allowed domains "
                    f"in domain {chat_client.provider.identity.domain}. "
                    f"External messaging should be restricted to allowed domains only."
                )

            findings.append(report)

        return findings
