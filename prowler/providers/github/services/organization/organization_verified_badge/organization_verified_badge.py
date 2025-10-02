from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.organization.organization_client import (
    organization_client,
)


class organization_verified_badge(Check):
    """Check if organization has a verified badge.

    This class verifies whether each organization has a verified badge on its profile page.
    A verified badge confirms the authenticity of the organization and helps protect against
    phishing attacks and domain spoofing.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Organization Verified Badge check.

        Iterates over all organizations and checks if they have a verified badge.

        Returns:
            List[CheckReportGithub]: A list of reports for each organization
        """
        findings = []
        for org in organization_client.organizations.values():
            if org.is_verified is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=org)
                report.status = "FAIL"
                report.status_extended = (
                    f"Organization {org.name} does not have a verified badge."
                )

                if org.is_verified:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Organization {org.name} has a verified badge."
                    )

                findings.append(report)

        return findings
