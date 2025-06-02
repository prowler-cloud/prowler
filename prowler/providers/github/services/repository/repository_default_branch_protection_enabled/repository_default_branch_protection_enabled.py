from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_protection_enabled(Check):
    """Check if a repository enforces default branch protection

    This class verifies whether each repository enforces default branch protection.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Enforces Default Branch Protection check

        Iterates over all repositories and checks if they enforce default branch protection.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.default_branch.protected is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.name} does not enforce branch protection on default branch ({repo.default_branch.name})."

                if repo.default_branch.protected:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} does enforce branch protection on default branch ({repo.default_branch.name})."

                findings.append(report)

        return findings
