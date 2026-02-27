from datetime import datetime, timezone
from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.team.team_client import team_client


class team_member_no_stale_access(Check):
    """Check if any Vercel team members have stale access.

    This class verifies that no active team members have a join date
    older than 90 days without review, which may indicate stale access
    that should be audited.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Team Member No Stale Access check.

        Iterates over all teams and checks for active members who joined
        more than 90 days ago.

        Returns:
            List[CheckReportVercel]: A list of reports for each team.
        """
        findings = []
        for team in team_client.teams.values():
            report = CheckReportVercel(
                metadata=self.metadata(),
                resource=team,
                resource_name=team.name,
                resource_id=team.id,
            )

            now = datetime.now(timezone.utc)
            stale_threshold_days = 90
            stale_members = []

            for member in team.members:
                if member.status != "active":
                    continue
                if member.joined_at is None:
                    continue

                # Ensure joined_at is timezone-aware for comparison
                joined_at = member.joined_at
                if joined_at.tzinfo is None:
                    joined_at = joined_at.replace(tzinfo=timezone.utc)

                age_days = (now - joined_at).days
                if age_days > stale_threshold_days:
                    stale_members.append(member)

            if not stale_members:
                report.status = "PASS"
                report.status_extended = (
                    f"Team {team.name} has no members with access older "
                    f"than {stale_threshold_days} days requiring review."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Team {team.name} has {len(stale_members)} member(s) "
                    f"who joined more than {stale_threshold_days} days ago "
                    f"and may require an access review."
                )

            findings.append(report)

        return findings
