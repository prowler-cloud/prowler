from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_shared_drive_creation_allowed(Check):
    """Check that users are allowed to create new shared drives

    This check verifies that the domain-level Drive and Docs policy permits
    users to create new shared drives. Allowing shared drive creation helps
    prevent data loss when individual user accounts are deleted, since
    content lives in shared drives owned by the organization rather than
    in personal My Drive folders.
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

            allow_creation = drive_client.policies.allow_shared_drive_creation

            if allow_creation is True:
                report.status = "PASS"
                report.status_extended = (
                    f"Users in domain {drive_client.provider.identity.domain} "
                    f"are allowed to create new shared drives."
                )
            elif allow_creation is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Shared drive creation uses Google's secure default "
                    f"configuration (allowed) "
                    f"in domain {drive_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Users in domain {drive_client.provider.identity.domain} "
                    f"are prevented from creating new shared drives. "
                    f"Users should be allowed to create new shared drives to avoid "
                    f"data loss when accounts are deleted."
                )

            findings.append(report)

        return findings
