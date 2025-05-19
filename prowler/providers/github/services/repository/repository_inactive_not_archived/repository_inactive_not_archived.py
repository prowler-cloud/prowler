from datetime import datetime, timezone
from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class repository_inactive_not_archived(Check):
    """Check if unarchived repositories have been inactive for more than 6 months."""

    def execute(self) -> List[CheckReportGithub]:
        findings = []

        now = datetime.now(timezone.utc)

        for repo in repository_client.repositories.values():
            report = CheckReportGithub(
                metadata=self.metadata(), resource=repo, repository=repo.name
            )

            if repo.archived:
                report.status = "PASS"
                report.status_extended = (
                    f"Repository {repo.full_name} is properly archived."
                )
                findings.append(report)
                continue

            latest_activity = repo.pushed_at
            months_inactive = (
                now - latest_activity
            ).days / 30.44  # Average days per month

            if months_inactive >= 6:
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.full_name} has been inactive for {int(months_inactive)} months and is not archived."
            else:
                report.status = "PASS"
                report.status_extended = f"Repository {repo.full_name} has been active within the last 6 months."

            findings.append(report)

        return findings
