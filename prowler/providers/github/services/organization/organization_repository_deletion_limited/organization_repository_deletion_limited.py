from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.organization.organization_client import (
    organization_client,
)


class organization_repository_deletion_limited(Check):
    """Check if repository deletion/transfer is limited to trusted organization users."""

    def execute(self) -> List[CheckReportGithub]:
        findings = []
        for org in organization_client.organizations.values():
            members_can_delete = org.members_can_delete_repositories

            if members_can_delete is None:
                continue

            report = CheckReportGithub(metadata=self.metadata(), resource=org)

            if members_can_delete is False:
                report.status = "PASS"
                report.status_extended = f"Organization {org.name} restricts repository deletion/transfer to trusted users."
            else:
                report.status = "FAIL"
                report.status_extended = f"Organization {org.name} allows members to delete/transfer repositories."

            findings.append(report)

        return findings
