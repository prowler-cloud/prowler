from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_immutable_releases_enabled(Check):
    """Ensure immutable releases are enabled for GitHub repositories.

    Immutable releases prevent post-publication tampering of binaries and release assets.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Run the immutable releases verification for each discovered repository.

        Returns:
            List[CheckReportGithub]: Collection of check reports describing the immutable releases status.
        """
        findings: List[CheckReportGithub] = []
        for repo in repository_client.repositories.values():
            if repo.immutable_releases_enabled is None:
                continue

            report = CheckReportGithub(metadata=self.metadata(), resource=repo)

            if repo.immutable_releases_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Repository {repo.name} has immutable releases enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Repository {repo.name} does not have immutable releases enabled."
                )

            findings.append(report)

        return findings
