from typing import List

from prowler.lib.check.models import Check, Check_Report_Github
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_public_has_securitymd_file(Check):
    """Check if a public repository has a SECURITY.md file

    This class verifies whether each public repository has a SECURITY.md file.
    """

    def execute(self) -> List[Check_Report_Github]:
        """Execute the Github Repository Public Has SECURITY.md File check

        Iterates over all public repositories and checks if they have a SECURITY.md file.

        Returns:
            List[Check_Report_Github]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            if not repo.private:
                report = Check_Report_Github(
                    metadata=self.metadata(), resource_metadata=repo
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
