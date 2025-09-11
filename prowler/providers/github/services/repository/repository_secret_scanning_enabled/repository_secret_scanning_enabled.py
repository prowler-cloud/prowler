from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_secret_scanning_enabled(Check):
    """Check if secret scanning is enabled to detect sensitive data in the repository

    This class verifies whether each repository has secret scanning enabled.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Secret Scanning check

        Iterates over all repositories and checks if secret scanning is enabled.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.secret_scanning_enabled is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                if getattr(repo, "secret_scanning_enabled", None):
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} has secret scanning enabled to detect sensitive data."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Repository {repo.name} does not have secret scanning enabled to detect sensitive data."

                findings.append(report)

        return findings
