from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_internal_users_distribute_content(Check):
    """Check that only internal users can distribute content externally

    This check verifies that the domain-level Drive and Docs policy restricts
    distributing content to shared drives owned by another organization to
    eligible internal users only, preventing external collaborators from
    moving organizational content out of the domain.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if drive_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=drive_client.provider.domain_resource,
            )

            allowed = drive_client.policies.allowed_parties_for_distributing_content

            if allowed in ("ELIGIBLE_INTERNAL_USERS", "NONE"):
                report.status = "PASS"
                report.status_extended = (
                    f"Distributing content outside the organization in domain "
                    f"{drive_client.provider.identity.domain} is restricted to "
                    f"{allowed}."
                )
            else:
                report.status = "FAIL"
                if allowed is None:
                    report.status_extended = (
                        f"Allowed parties for distributing content externally is not "
                        f"explicitly configured in domain "
                        f"{drive_client.provider.identity.domain}. "
                        f"Only internal users should be allowed to distribute content externally."
                    )
                else:
                    report.status_extended = (
                        f"Distributing content outside the organization in domain "
                        f"{drive_client.provider.identity.domain} is set to {allowed}. "
                        f"Only internal users should be allowed to distribute content externally."
                    )

            findings.append(report)

        return findings
