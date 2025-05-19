from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_has_codeowners_file(Check):
    """Check if a repository has a CODEOWNERS file

    This class verifies whether each repository has a CODEOWNERS file.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository CODEOWNERS file existence check

        Iterates over all repositories and checks if they have a CODEOWNERS file.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if repo.codeowners_exists is not None:
                report = CheckReportGithub(
                    metadata=self.metadata(), resource=repo, repository=repo.name
                )
                if repo.codeowners_exists:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Repository {repo.full_name} does have a CODEOWNERS file."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Repository {repo.full_name} does not have a CODEOWNERS file."
                    )

                findings.append(report)

        return findings
