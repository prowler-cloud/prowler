from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_status_checks_required(Check):
    """Check if a repository enforces status checks.

    This class verifies whether each repository enforces status checks.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository

        Iterates over all repositories and checks if they enforce status checks.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository.
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.default_branch.status_checks is not None:
                report = CheckReportGithub(self.metadata(), resource=repo)
                report.status = "FAIL"
                report.status_extended = (
                    f"Repository {repo.name} does not enforce status checks."
                )

                if repo.default_branch.status_checks:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Repository {repo.name} does enforce status checks."
                    )

                findings.append(report)

        return findings
