from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_default_branch_dismisses_stale_reviews(Check):
    """Check if a repository dismisses stale pull request approvals when new commits are pushed.

    This class verifies whether each repository is configured to automatically
    invalidate existing approvals when new commits are pushed to an open pull request.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the check.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository.
        """
        findings = []

        for repo in repository_client.repositories.values():

            # On ignore les cas où on n'a pas pu déterminer la valeur (erreur API)
            if repo.default_branch.dismiss_stale_reviews is not None:

                report = CheckReportGithub(metadata=self.metadata(), resource=repo)

                # Par défaut : FAIL
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.name} does not dismiss stale pull request approvals when new commits are pushed."

                if repo.default_branch.dismiss_stale_reviews:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repo.name} does dismiss stale pull request approvals when new commits are pushed."

                findings.append(report)

        return findings