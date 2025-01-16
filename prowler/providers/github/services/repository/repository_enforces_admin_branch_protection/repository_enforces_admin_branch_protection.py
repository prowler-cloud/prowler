from typing import List

from prowler.lib.check.models import Check, Check_Report_Github
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_enforces_admin_branch_protection(Check):
    """Check if a repository enforces administrators to be subject to the same branch protection rules as other users

    This class verifies whether each repository enforces administrators to be subject to the same branch protection rules as other users.
    """

    def execute(self) -> List[Check_Report_Github]:
        """Execute the Github Repository Enforces Admin Branch Protection check

        Iterates over all repositories and checks if they enforce administrators to be subject to the same branch protection rules as other users.

        Returns:
            List[Check_Report_Github]: A list of reports for each repository.
        """
        findings = []
        for repo in repository_client.repositories.values():
            report = Check_Report_Github(
                metadata=self.metadata(), resource_metadata=repo
            )
            report.status = "FAIL"
            report.status_extended = f"Repository {repo.name} does not enforce administrators to be subject to the same branch protection rules as other users."

            if (
                repo.default_branch_protection
                and repo.default_branch_protection.enforce_admins
            ):
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} does enforce administrators to be subject to the same branch protection rules as other users."

            findings.append(report)

        return findings
