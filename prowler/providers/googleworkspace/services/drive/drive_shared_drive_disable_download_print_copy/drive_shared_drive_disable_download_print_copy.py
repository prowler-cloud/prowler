from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_shared_drive_disable_download_print_copy(Check):
    """Check that download/print/copy is disabled for viewers and commenters

    This check verifies that the domain-level Drive and Docs policy prevents
    viewers and commenters of shared drive files from downloading, printing,
    or copying their contents — limiting them to read and comment actions
    only and reducing the risk of bulk data exfiltration.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if drive_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=drive_client.provider.identity,
                resource_name=drive_client.provider.identity.domain,
                resource_id=drive_client.provider.identity.customer_id,
                customer_id=drive_client.provider.identity.customer_id,
                location="global",
            )

            allowed = drive_client.policies.allowed_parties_for_download_print_copy

            if allowed in ("EDITORS_ONLY", "MANAGERS_ONLY"):
                report.status = "PASS"
                report.status_extended = (
                    f"Download, print, and copy in shared drives in domain "
                    f"{drive_client.provider.identity.domain} is restricted to "
                    f"{allowed}."
                )
            elif allowed is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Download, print, and copy restrictions for shared drives use "
                    f"Google's secure default configuration (disabled for viewers "
                    f"and commenters) "
                    f"in domain {drive_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Download, print, and copy in shared drives in domain "
                    f"{drive_client.provider.identity.domain} is set to {allowed}. "
                    f"These actions should be restricted to editors or managers only."
                )

            findings.append(report)

        return findings
