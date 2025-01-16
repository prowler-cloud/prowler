from typing import List

from prowler.lib.check.models import Check, Check_Report_Github
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_deletes_branch_on_merge(Check):
    """Check if a repository deletes branches on merge

    This class verifies whether each repository deletes branches on merge.
    """

    def execute(self) -> List[Check_Report_Github]:
        """Execute the Github Repository Deletes Branch On Merge check

        Iterates over all repositories and checks if they delete branches on merge.

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
                f"Repository {repo.name} does not delete branches on merge."
            )

            if repo.delete_branch_on_merge:
                report.status = "PASS"
                report.status_extended = (
                    f"Repository {repo.name} does delete branches on merge."
                )

            findings.append(report)

        return findings
