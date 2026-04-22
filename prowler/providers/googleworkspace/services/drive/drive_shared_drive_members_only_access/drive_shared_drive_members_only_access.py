from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_shared_drive_members_only_access(Check):
    """Check that shared drive file access is restricted to members only

    This check verifies that the domain-level Drive and Docs policy prevents
    people who are not shared drive members from being added to files within
    a shared drive, restricting file access to that drive's explicit
    membership.
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
                if allow_non_member is None:
                    report.status_extended = (
                        f"Shared drive non-member access is not explicitly "
                        f"configured in domain {drive_client.provider.identity.domain}. "
                        f"Shared drive file access should be restricted to members only."
                    )
                else:
                    report.status_extended = (
                        f"Shared drive file access in domain "
                        f"{drive_client.provider.identity.domain} allows non-members "
                        f"to be added to files. "
                        f"Shared drive file access should be restricted to members only."
                    )

            findings.append(report)

        return findings
