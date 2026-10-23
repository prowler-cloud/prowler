from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.organization.organization_client import (
    organization_client,
)


class organization_actions_pull_request_approval_disabled(Check):
    """Check if GitHub Actions workflows are prevented from approving pull requests.

    This class verifies whether each organization disallows workflows from creating and
    approving pull requests, so that required reviews cannot be satisfied by automation.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Organization Actions Pull Request Approval Disabled check.

        Iterates over all organizations and checks whether GitHub Actions workflows are
        allowed to approve pull requests.

        Returns:
            List[CheckReportGithub]: A list of reports for each organization
        """
        findings = []
        for org in organization_client.organizations.values():
            if org.can_approve_pull_request_reviews is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=org)
                report.status = "PASS"
                report.status_extended = f"Organization {org.name} does not allow GitHub Actions to approve pull requests."

                if org.can_approve_pull_request_reviews:
                    report.status = "FAIL"
                    report.status_extended = f"Organization {org.name} allows GitHub Actions to approve pull requests."

                findings.append(report)

        return findings
