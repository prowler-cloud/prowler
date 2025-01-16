from typing import List

from prowler.lib.check.models import Check, Check_Report_Github
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_denies_branch_deletion(Check):
    """Check if a repository denies branch deletion

    This class verifies whether each repository denies branch deletion.
    """

    def execute(self) -> List[Check_Report_Github]:
        """Execute the Github Repository Denies Branch Deletion check

        Iterates over all repositories and checks if they deny branch deletion.

        Returns:
            List[Check_Report_Github]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            report = Check_Report_Github(
                metadata=self.metadata(), resource_metadata=repo
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Repository {repo.name} does allow branch deletion."
            )

            if (
                repo.default_branch_protection
                and not repo.default_branch_protection.allow_branch_deletion
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Repository {repo.name} does deny branch deletion."
                )

            findings.append(report)

        return findings
