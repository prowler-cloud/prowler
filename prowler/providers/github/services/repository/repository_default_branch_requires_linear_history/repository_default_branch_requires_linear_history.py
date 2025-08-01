from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_requires_linear_history(Check):
    """Check if a repository requires linear history on default branch

    This class verifies whether each repository requires linear history on the default branch.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Merging Requires Linear History check

        Iterates over all repositories and checks if they require linear history on the default branch.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.default_branch.required_linear_history is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.name} does not require linear history on default branch ({repo.default_branch.name})."

                if repo.default_branch.required_linear_history:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} does require linear history on default branch ({repo.default_branch.name})."

                findings.append(report)

        return findings
