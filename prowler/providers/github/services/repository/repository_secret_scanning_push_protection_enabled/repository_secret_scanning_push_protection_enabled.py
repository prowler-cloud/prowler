from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_secret_scanning_push_protection_enabled(Check):
    """Check if secret scanning push protection is enabled for the repository

    This class verifies whether each repository blocks pushes that contain
    supported secrets before they reach the Git history.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Secret Scanning Push Protection check

        Iterates over all repositories and checks if push protection is enabled.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.secret_scanning_push_protection_enabled is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                if repo.secret_scanning_push_protection_enabled:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} has secret scanning push protection enabled to block commits containing secrets."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Repository {repo.name} does not have secret scanning push protection enabled, so commits containing secrets are accepted."

                findings.append(report)

        return findings
