from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_requires_signed_commits(Check):
    """Check if a repository requires signed commits

    This class verifies whether each repository requires signed commits for the default branch.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Requires Signed Commits check

        Iterates over all repositories and checks if they require signed commits.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.default_branch.require_signed_commits is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.name} does not require signed commits on default branch ({repo.default_branch.name})."

                if repo.default_branch.require_signed_commits:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} does require signed commits on default branch ({repo.default_branch.name})."

                findings.append(report)

        return findings
