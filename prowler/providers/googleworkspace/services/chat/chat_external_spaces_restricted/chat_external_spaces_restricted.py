from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.chat.chat_client import chat_client


class chat_external_spaces_restricted(Check):
    """Check that external spaces in Google Chat are restricted.

    This check verifies that external spaces are either disabled entirely
    or restricted to allowlisted domains only, preventing users from
    creating or joining spaces with unrestricted external participants.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if chat_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=chat_client.provider.domain_resource,
            )

            spaces_enabled = chat_client.policies.external_spaces_enabled
            allowlist_mode = chat_client.policies.external_spaces_domain_allowlist_mode

            if spaces_enabled is False:
                report.status = "PASS"
                report.status_extended = (
                    f"External spaces are disabled "
                    f"in domain {chat_client.provider.identity.domain}."
                )
            elif allowlist_mode == "TRUSTED_DOMAINS":
                report.status = "PASS"
                report.status_extended = (
                    f"External spaces are restricted to allowed domains "
                    f"in domain {chat_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if spaces_enabled is None and allowlist_mode is None:
                    report.status_extended = (
                        f"External spaces restriction is not explicitly configured "
                        f"in domain {chat_client.provider.identity.domain}. "
                        f"External spaces should be restricted to allowed domains only."
                    )
                else:
                    report.status_extended = (
                        f"External spaces are not restricted to allowed domains "
                        f"in domain {chat_client.provider.identity.domain}. "
                        f"External spaces should be restricted to allowed domains only."
                    )

            findings.append(report)

        return findings
