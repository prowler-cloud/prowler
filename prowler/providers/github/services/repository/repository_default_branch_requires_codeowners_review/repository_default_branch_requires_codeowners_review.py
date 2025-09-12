from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_requires_codeowners_review(Check):
    """Check if code owner approval is required for changes to owned code

    This class verifies whether each repository requires code owner review for changes to code they own.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Code Owner Approval Requirement check

        Iterates over all repositories and checks if they require code owner review for changes.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.default_branch.require_code_owner_reviews is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                if repo.default_branch.require_code_owner_reviews:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} requires code owner approval for changes to owned code."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Repository {repo.name} does not require code owner approval for changes to owned code."

                findings.append(report)

        return findings
