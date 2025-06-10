from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_branch_delete_on_merge_enabled(Check):
    """Check if a repository deletes branches on merge

    This class verifies whether each repository deletes branches on merge.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Deletes Branch On Merge check

        Iterates over all repositories and checks if they delete branches on merge.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            report = CheckReportGithub(metadata=self.metadata(), resource=repo)
            report.status = "FAIL"
            report.status_extended = f"Repository {repo.name} does not delete branches on merge in default branch ({repo.default_branch.name})."

            if repo.delete_branch_on_merge:
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} does delete branches on merge in default branch ({repo.default_branch.name})."

            findings.append(report)

        return findings
