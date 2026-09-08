from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_workflow_permissions_read_only(Check):
    """Ensure repositories grant workflows a read-only default GITHUB_TOKEN.

    A read-only default forces workflows to request write access explicitly, instead of
    every workflow run starting with a token that can write to the repository.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Run the default workflow permissions verification for each discovered repository.

        Returns:
            List[CheckReportGithub]: Collection of check reports describing the default GITHUB_TOKEN permissions.
        """
        findings: List[CheckReportGithub] = []
        for repo in repository_client.repositories.values():
            if repo.default_workflow_permissions is None:
                continue

            report = CheckReportGithub(metadata=self.metadata(), resource=repo)

            if repo.default_workflow_permissions == "read":
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} grants workflows a read-only default GITHUB_TOKEN."
            else:
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.name} grants workflows a default GITHUB_TOKEN with {repo.default_workflow_permissions} permissions."

            findings.append(report)

        return findings
