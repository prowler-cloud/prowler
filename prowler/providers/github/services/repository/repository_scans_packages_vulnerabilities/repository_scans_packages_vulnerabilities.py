from typing import List

from prowler.lib.check.models import Check, Check_Report_Github
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_scans_packages_vulnerabilities(Check):
    """Check if a repository scans packages for vulnerabilities

    This class verifies whether each public repository scans packages for vulnerabilities.
    """

    def execute(self) -> List[Check_Report_Github]:
        """Execute the Github Repository Scans Packages Vulnerabilities check

        Iterates over all repositories and checks if they scan packages for vulnerabilities.

        Returns:
            List[Check_Report_Github]: A list of reports for each repository
        """
        findings = []
        for repo in repository_client.repositories.values():
            report = Check_Report_Github(self.metadata())
            report.resource_id = repo.id
            report.resource_name = repo.name
            report.status = "FAIL"
            report.status_extended = f"Repository {repo.name} does not scan vulnerabilities in used packages."

            if repo.dependabot_enabled:
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} does scan vulnerabilities in used packages."

            findings.append(report)

        return findings
