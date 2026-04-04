from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_ruleset_dismisses_stale_reviews(Check):
    """Check if a repository ruleset dismisses stale reviews when new commits are pushed.

    This class verifies whether each repository has an active ruleset that
    dismisses stale pull request approvals when new commits are pushed.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the check for stale review dismissal via repository rulesets.

        Returns:
            List[CheckReportGithub]: A list of reports for each repository.
        """
        findings = []
        for repo in repository_client.repositories.values():
            report = CheckReportGithub(metadata=self.metadata(), resource=repo)

            if repo.archived:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Repository {repo.name} is archived and not actively maintained."
                )
                findings.append(report)
                continue

            if repo.rulesets:
                passing_ruleset = next(
                    (
                        rs
                        for rs in repo.rulesets
                        if rs.enforcement == "active"
                        and rs.dismiss_stale_reviews_on_push
                        and rs.target == "branch"
                    ),
                    None,
                )
                if passing_ruleset:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Repository {repo.name} has an active ruleset "
                        f"'{passing_ruleset.name}' that dismisses stale reviews on push."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Repository {repo.name} has rulesets but none enforce "
                        f"dismissal of stale reviews on push."
                    )
                findings.append(report)
                continue

            branch = repo.default_branch
            if branch is None or branch.protected is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Repository {repo.name}: branch protection status could not be determined."
                )
                findings.append(report)
                continue

            if not branch.protected:
                report.status = "FAIL"
                report.status_extended = (
                    f"Repository {repo.name} default branch '{branch.name}' "
                    f"has no branch protection or ruleset configured."
                )
                findings.append(report)
                continue

            report.status = "MANUAL"
            report.status_extended = (
                f"Repository {repo.name} uses legacy branch protection rules. "
                f"Migrate to GitHub Repository Rulesets and enable "
                f"'Dismiss stale reviews on push' to allow automated verification."
            )
            findings.append(report)

        return findings
