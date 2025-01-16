from typing import List

from prowler.lib.check.models import Check, Check_Report_Github
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_enforces_status_checks(Check):
    """Check if a repository enforces status checks.

    This class verifies whether each repository enforces status checks.
    """

    def execute(self) -> List[Check_Report_Github]:
        """Execute the Github Repository

        Iterates over all repositories and checks if they enforce status checks.

        Returns:
            List[Check_Report_Github]: A list of reports for each repository.
        """
        findings = []
        for repo in repository_client.repositories.values():
            report = Check_Report_Github(self.metadata())
            report.status = "FAIL"
            report.status_extended = (
                f"Repository {repo.name} does not enforce status checks."
            )

            if (
                repo.default_branch_protection
                and repo.default_branch_protection.enforce_status_checks
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Repository {repo.name} does enforce status checks."
                )

            findings.append(report)

        return findings
