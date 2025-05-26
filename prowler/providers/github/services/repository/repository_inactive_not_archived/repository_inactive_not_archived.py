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

        days_threshold = repository_client.audit_config.get(
            "inactive_not_archived_days_threshold", 180
        )

        for repo in repository_client.repositories.values():
            report = CheckReportGithub(metadata=self.metadata(), resource=repo)

            if repo.archived:
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} is properly archived."
                findings.append(report)
                continue

            latest_activity = repo.pushed_at
            days_inactive = (now - latest_activity).days

            if days_inactive >= days_threshold:
                report.status = "FAIL"
                report.status_extended = f"Repository {repo.name} has been inactive for {days_inactive} days and is not archived (threshold: {days_threshold} days)."
            else:
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} has been active within the last {days_threshold} days ({days_inactive} days ago)."

            findings.append(report)

        return findings
