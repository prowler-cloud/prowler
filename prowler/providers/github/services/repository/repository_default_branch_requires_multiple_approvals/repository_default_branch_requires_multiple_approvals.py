from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_requires_multiple_approvals(Check):
    """Check if a repository enforces at least 2 approvals for code changes

    This class verifies whether each repository enforces at least 2 approvals for code changes.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository code changes enforce multi approval requirement check

        Iterates over each repository and checks if the repository enforces at least 2 approvals for code changes.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.default_branch.approval_count is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.name} does not enforce at least 2 approvals for code changes."

                if repo.default_branch.approval_count >= 2:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} does enforce at least 2 approvals for code changes."

                findings.append(report)

        return findings
