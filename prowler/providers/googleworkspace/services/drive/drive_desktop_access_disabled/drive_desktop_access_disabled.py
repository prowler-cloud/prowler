from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_desktop_access_disabled(Check):
    """Check that Google Drive for desktop is disabled

    This check verifies that the domain-level Drive and Docs policy disables
    Google Drive for desktop. The desktop client synchronizes Drive content
    to local devices and bypasses the standard offline access controls,
    so disabling it reduces the risk of organizational data being lost or
    stolen along with an end-user device.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if drive_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=drive_client.provider.domain_resource,
            )

            allow_desktop = drive_client.policies.allow_drive_for_desktop

            if allow_desktop is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Google Drive for desktop is disabled in domain "
                    f"{drive_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if allow_desktop is None:
                    report.status_extended = (
                        f"Google Drive for desktop is not explicitly configured "
                        f"in domain {drive_client.provider.identity.domain}. "
                        f"Drive for desktop should be disabled to prevent local "
                        f"synchronization of organizational content."
                    )
                else:
                    report.status_extended = (
                        f"Google Drive for desktop is enabled in domain "
                        f"{drive_client.provider.identity.domain}. "
                        f"Drive for desktop should be disabled to prevent local "
                        f"synchronization of organizational content."
                    )

            findings.append(report)

        return findings
