from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.chat.chat_client import chat_client


class chat_apps_installation_disabled(Check):
    """Check that users cannot install Chat apps.

    This check verifies that the domain-level Chat policy prevents users
    from installing Chat apps, reducing the risk of data exposure through
    third-party or unvetted applications.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if chat_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=chat_client.provider.domain_resource,
            )

            apps_enabled = chat_client.policies.enable_apps

            if apps_enabled is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Chat apps installation is disabled "
                    f"in domain {chat_client.provider.identity.domain}."
                )
            elif apps_enabled is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Chat apps installation uses Google's secure default "
                    f"configuration (disabled) "
                    f"in domain {chat_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Chat apps installation is enabled "
                    f"in domain {chat_client.provider.identity.domain}. "
                    f"Chat apps installation should be disabled to prevent unvetted apps."
                )

            findings.append(report)

        return findings
