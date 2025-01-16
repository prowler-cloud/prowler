from typing import List

from prowler.lib.check.models import Check, Check_Report_Github
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_code_changes_multi_approval_requirement(Check):
    """Check if a repository enforces at least 2 approvals for code changes

    This class verifies whether each repository enforces at least 2 approvals for code changes.
    """

    def execute(self) -> List[Check_Report_Github]:
        """Execute the Github Repository code changes enforce multi approval requirement check

        Iterates over each repository and checks if the repository enforces at least 2 approvals for code changes.

        Returns:
            List[Check_Report_Github]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            report = Check_Report_Github(
                metadata=self.metadata(), resource_metadata=repo
            )
            report.status = "FAIL"
            report.status_extended = f"Repository {repo.name} does not enforce at least 2 approvals for code changes."

            if repo.approval_count >= 2:
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} does enforce at least 2 approvals for code changes."

            findings.append(report)

        return findings
