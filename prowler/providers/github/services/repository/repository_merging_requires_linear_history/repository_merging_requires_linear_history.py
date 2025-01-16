from typing import List

from prowler.lib.check.models import Check, Check_Report_Github
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_merging_requires_linear_history(Check):
    """Check if a repository requires linear history on default branch

    This class verifies whether each repository requires linear history on the default branch.
    """

    def execute(self) -> List[Check_Report_Github]:
        """Execute the Github Repository Merging Requires Linear History check

        Iterates over all repositories and checks if they require linear history on the default branch.

        Returns:
            List[Check_Report_Github]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            report = Check_Report_Github(
                metadata=self.metadata(), resource_metadata=repo
            )
            report.resource_id = repo.id
            report.resource_name = repo.name
            report.status = "FAIL"
            report.status_extended = f"Repository {repo.name} does not require linear history on default branch ({repo.default_branch})."

            if (
                repo.default_branch_protection
                and repo.default_branch_protection.linear_history
            ):
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} does require linear history on default branch ({repo.default_branch})."

            findings.append(report)

        return findings
