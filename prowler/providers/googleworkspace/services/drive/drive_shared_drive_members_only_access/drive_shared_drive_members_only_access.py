from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.lib.licensing import (
    EDITIONS_WITHOUT_SHARED_DRIVE_SETTINGS,
    SHARED_DRIVE_SETTINGS_EXPLANATION,
    edition_reason_suffix,
)
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_shared_drive_members_only_access(Check):
    """Check that shared drive file access is restricted to members only

    This check verifies that the domain-level Drive and Docs policy prevents
    people who are not shared drive members from being added to files within
    a shared drive, restricting file access to that drive's explicit
    membership. The setting is edition-gated: when every edition the tenant
    holds lacks it, the finding says so.
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

            allow_non_member = drive_client.policies.allow_non_member_access

            if allow_non_member is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Shared drive file access in domain "
                    f"{drive_client.provider.identity.domain} is restricted to "
                    f"shared drive members only."
                )
            else:
                report.status = "FAIL"
                edition_reason = edition_reason_suffix(
                    drive_client.provider.editions,
                    EDITIONS_WITHOUT_SHARED_DRIVE_SETTINGS,
                    SHARED_DRIVE_SETTINGS_EXPLANATION,
                )
                if allow_non_member is None:
                    report.status_extended = (
                        f"Shared drive non-member access is not explicitly "
                        f"configured in domain {drive_client.provider.identity.domain}. "
                        f"Shared drive file access should be restricted to members only."
                        f"{edition_reason}"
                    )
                else:
                    report.status_extended = (
                        f"Shared drive file access in domain "
                        f"{drive_client.provider.identity.domain} allows non-members "
                        f"to be added to files. "
                        f"Shared drive file access should be restricted to members only."
                        f"{edition_reason}"
                    )

            findings.append(report)

        return findings
