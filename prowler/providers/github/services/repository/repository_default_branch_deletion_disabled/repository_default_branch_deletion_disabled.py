from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_deletion_disabled(Check):
    """Check if a repository denies branch deletion

    This class verifies whether each repository denies default branch deletion.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Denies Default Branch Deletion check

        Iterates over all repositories and checks if they deny default branch deletion.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.default_branch.branch_deletion is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=repo)
                report.status = "FAIL"
                report.status_extended = (
                    f"Repository {repo.name} does allow default branch deletion."
                )

                if not repo.default_branch.branch_deletion:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Repository {repo.name} does deny default branch deletion."
                    )

                findings.append(report)

        return findings
