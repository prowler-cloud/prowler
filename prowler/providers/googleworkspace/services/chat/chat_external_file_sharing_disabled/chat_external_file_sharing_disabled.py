from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.chat.chat_client import chat_client


class chat_external_file_sharing_disabled(Check):
    """Check that external file sharing in Google Chat is disabled.

    This check verifies that the domain-level Chat policy prevents users
    from sharing files with people outside the organization via Chat,
    protecting sensitive information from unauthorized external access.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if chat_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=chat_client.policies,
                resource_id="chatPolicies",
                resource_name="Chat Policies",
                customer_id=chat_client.provider.identity.customer_id,
            )

            external_sharing = chat_client.policies.external_file_sharing

            if external_sharing == "NO_FILES":
                report.status = "PASS"
                report.status_extended = (
                    f"External file sharing in Chat is disabled "
                    f"in domain {chat_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if external_sharing is None:
                    report.status_extended = (
                        f"External file sharing in Chat is not explicitly configured "
                        f"in domain {chat_client.provider.identity.domain}. "
                        f"External file sharing should be set to No files."
                    )
                else:
                    report.status_extended = (
                        f"External file sharing in Chat is set to {external_sharing} "
                        f"in domain {chat_client.provider.identity.domain}. "
                        f"External file sharing should be set to No files."
                    )

            findings.append(report)

        return findings
