from typing import List

from prowler.lib.check.models import Check, Check_Report_Github
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_merging_requires_conversation_resolution(Check):
    """Check if a repository requires conversation resolution

    This class verifies whether each repository requires conversation resolution.
    """

    def execute(self) -> List[Check_Report_Github]:
        """Execute the Github Repository Merging Requires Conversation Resolution check

        Iterates over all repositories and checks if they require conversation resolution.

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
                f"Repository {repo.name} does not require conversation resolution."
            )

            if (
                repo.default_branch_protection
                and repo.default_branch_protection.conversation_resolution
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Repository {repo.name} does require conversation resolution."
                )

            findings.append(report)

        return findings
