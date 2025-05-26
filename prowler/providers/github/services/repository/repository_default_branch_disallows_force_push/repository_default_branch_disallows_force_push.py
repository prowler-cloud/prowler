from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_disallows_force_push(Check):
    """Check if a repository denies force push

    This class verifies whether each repository denies force push.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Denies Force Push check

        Iterates over all repositories and checks if they deny force push.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.default_branch.allow_force_pushes is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.name} does allow force pushes on default branch ({repo.default_branch.name})."

                if not repo.default_branch.allow_force_pushes:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} does deny force pushes on default branch ({repo.default_branch.name})."

                findings.append(report)

        return findings
