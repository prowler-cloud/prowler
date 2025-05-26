from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_requires_conversation_resolution(Check):
    """Check if a repository requires conversation resolution

    This class verifies whether each repository requires conversation resolution.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Merging Requires Conversation Resolution check

        Iterates over all repositories and checks if they require conversation resolution.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.default_branch.conversation_resolution is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.name} does not require conversation resolution on default branch ({repo.default_branch.name})."

                if repo.default_branch.conversation_resolution:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} does require conversation resolution on default branch ({repo.default_branch.name})."

                findings.append(report)

        return findings
