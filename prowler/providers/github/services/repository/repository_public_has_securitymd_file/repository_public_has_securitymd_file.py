from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_public_has_securitymd_file(Check):
    """Check if a public repository has a SECURITY.md file

    This class verifies whether each public repository has a SECURITY.md file.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Repository Public Has SECURITY.md File check

        Iterates over all public repositories and checks if they have a SECURITY.md file.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if not repo.private and repo.securitymd is not None:
                report = CheckReportGithub(
                    metadata=self.metadata(), resource=repo, repository=repo.name
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Repository {repo.name} does have a SECURITY.md file."
                )

                if not repo.securitymd:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Repository {repo.name} does not have a SECURITY.md file."
                    )

                findings.append(report)

        return findings
