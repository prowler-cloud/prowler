from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_dependency_scanning_enabled(Check):
    """Check if package vulnerability scanning (Dependabot alerts) is enabled for dependencies in the repository

    This class verifies whether each repository has package vulnerability scanning enabled.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Package Vulnerabilities Scanner check

        Iterates over all repositories and checks if package vulnerability scanning is enabled.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.dependabot_alerts_enabled is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                if repo.dependabot_alerts_enabled:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} has package vulnerability scanning (Dependabot alerts) enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Repository {repo.name} does not have package vulnerability scanning (Dependabot alerts) enabled."

                findings.append(report)

        return findings
