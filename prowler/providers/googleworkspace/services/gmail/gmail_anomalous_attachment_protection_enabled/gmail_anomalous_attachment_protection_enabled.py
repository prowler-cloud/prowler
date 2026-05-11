from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_anomalous_attachment_protection_enabled(Check):
    """Check that protection against anomalous attachment types in emails is enabled.

    This check verifies that Gmail is configured to take action on
    emails containing unusual attachment types, helping prevent
    malware delivery via uncommon file formats.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.domain_resource,
            )

            enabled = gmail_client.policies.enable_anomalous_attachment_protection
            consequence = (
                gmail_client.policies.anomalous_attachment_protection_consequence
            )

            if enabled is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against anomalous attachment types in emails "
                    f"is disabled in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"Enable the protection and configure a protective action."
                )
            elif enabled is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against anomalous attachment types in emails "
                    f"is not configured and uses Google's insecure default "
                    f"(disabled) in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"Enable the protection and configure a protective action."
                )
            elif consequence == "NO_ACTION":
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against anomalous attachment types in emails "
                    f"is set to take no action in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"A protective action should be configured."
                )
            elif consequence is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against anomalous attachment types in emails "
                    f"is enabled in domain "
                    f"{gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against anomalous attachment types in emails "
                    f"is enabled with consequence '{consequence}' "
                    f"in domain {gmail_client.provider.identity.domain}."
                )

            findings.append(report)

        return findings
