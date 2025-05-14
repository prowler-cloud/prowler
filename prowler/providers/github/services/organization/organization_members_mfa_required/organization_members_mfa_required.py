from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.organization.organization_client import (
    organization_client,
)


class organization_members_mfa_required(Check):
    """Check if organization members are required to have two-factor authentication enabled.

    This class verifies whether each organization requires its members to have two-factor authentication enabled.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Organization Members MFA Required check.

        Iterates over all organizations and checks if members are required to have two-factor authentication enabled.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for org in organization_client.organizations.values():
            if org.mfa_required is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=org)
                report.status = "FAIL"
                report.status_extended = f"Organization {org.name} does not require members to have two-factor authentication enabled."

                if org.mfa_required:
                    report.status = "PASS"
                    report.status_extended = f"Organization {org.name} does require members to have two-factor authentication enabled."

                findings.append(report)

        return findings
