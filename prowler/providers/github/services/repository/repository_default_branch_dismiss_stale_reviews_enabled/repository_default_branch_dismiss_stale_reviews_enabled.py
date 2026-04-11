from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_dismiss_stale_reviews_enabled(Check):
    """Check if a repository dismisses stale pull request approvals when new commits are pushed

    This class verifies whether each repository has the dismiss stale reviews setting enabled on the default branch protection rule.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Dismiss Stale Reviews check

        Iterates over all repositories and checks if they dismiss stale pull request approvals when new commits are pushed.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.default_branch.dismiss_stale_reviews is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.name} does not dismiss stale pull request approvals when new commits are pushed on default branch ({repo.default_branch.name})."

                if repo.default_branch.dismiss_stale_reviews:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} does dismiss stale pull request approvals when new commits are pushed on default branch ({repo.default_branch.name})."

                findings.append(report)

        return findings
