from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_external_sharing_warn_users(Check):
    """Check that users are warned when sharing files outside the domain

    This check verifies that the domain-level Drive and Docs policy warns
    users when they attempt to share a file with someone outside the
    organization, reducing the risk of accidental information disclosure.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if drive_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=drive_client.policies,
                resource_id="drivePolicies",
                resource_name="Drive Policies",
                customer_id=drive_client.provider.identity.customer_id,
            )

            warning_enabled = drive_client.policies.warn_for_external_sharing

            if drive_client.policies.off_for_everyone:
                report.status = "PASS"
                report.status_extended = (
                    f"Google Drive is turned off for everyone in domain "
                    f"{drive_client.provider.identity.domain}, so no file can be shared outside the organization."
                )
            elif warning_enabled is True:
                report.status = "PASS"
                report.status_extended = (
                    f"External sharing warnings for Drive and Docs are enabled "
                    f"in domain {drive_client.provider.identity.domain}."
                )
            elif warning_enabled is None:
                report.status = "PASS"
                report.status_extended = (
                    f"External sharing warnings for Drive and Docs use Google's "
                    f"secure default configuration (enabled) "
                    f"in domain {drive_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"External sharing warnings for Drive and Docs are disabled "
                    f"in domain {drive_client.provider.identity.domain}. "
                    f"Users should be warned when sharing files outside the organization."
                )

            findings.append(report)

        return findings
