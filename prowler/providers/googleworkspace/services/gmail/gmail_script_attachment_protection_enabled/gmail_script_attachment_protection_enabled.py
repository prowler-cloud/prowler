from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_script_attachment_protection_enabled(Check):
    """Check that protection against attachments with scripts from untrusted senders is enabled.

    This check verifies that Gmail is configured to take action on
    attachments containing scripts from untrusted senders, helping
    prevent malware delivery via script-bearing files.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.domain_resource,
            )

            enabled = gmail_client.policies.enable_script_attachment_protection
            consequence = gmail_client.policies.script_attachment_protection_consequence

            if enabled is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against attachments with scripts from "
                    f"untrusted senders is disabled in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"Enable the protection and configure a protective action."
                )
            elif consequence == "NO_ACTION":
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against attachments with scripts from "
                    f"untrusted senders is set to take no action in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"A protective action should be configured."
                )
            elif consequence is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against attachments with scripts from "
                    f"untrusted senders uses Google's secure default "
                    f"configuration (enabled) in domain "
                    f"{gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against attachments with scripts from "
                    f"untrusted senders is enabled with consequence "
                    f"'{consequence}' in domain "
                    f"{gmail_client.provider.identity.domain}."
                )

            findings.append(report)

        return findings
