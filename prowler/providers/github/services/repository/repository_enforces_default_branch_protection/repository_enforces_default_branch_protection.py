from typing import List

from prowler.lib.check.models import Check, Check_Report_Github
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_enforces_default_branch_protection(Check):
    """Check if a repository enforces default branch protection

    This class verifies whether each repository enforces default branch protection.
    """

    def execute(self) -> List[Check_Report_Github]:
        """Execute the Github Repository Enforces Default Branch Protection check

        Iterates over all repositories and checks if they enforce default branch protection.

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
            report.status_extended = f"Repository {repo.name} does not enforce branch protection on default branch ({repo.default_branch})."

            if repo.default_branch_protection:
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} does enforce branch protection on default branch ({repo.default_branch})."

            findings.append(report)

        return findings
