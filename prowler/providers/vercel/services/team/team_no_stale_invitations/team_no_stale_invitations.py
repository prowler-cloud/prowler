from datetime import datetime, timezone
from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.team.team_client import team_client


class team_no_stale_invitations(Check):
    """Check if the Vercel team has stale pending invitations.

    This class verifies that no team invitations have been pending for
    more than 30 days, which may indicate abandoned or forgotten invitations
    that should be revoked.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Team No Stale Invitations check.

        Iterates over all teams and checks for pending invitations older
        than 30 days.

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
            stale_threshold_days = team_client.audit_config.get(
                "stale_invitation_threshold_days", 30
            )
            stale_invitations = []

            for member in team.members:
                if member.status != "invited":
                    continue
                if member.created_at is None:
                    continue

                # Ensure created_at is timezone-aware for comparison
                created_at = member.created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)

                age_days = (now - created_at).days
                if age_days > stale_threshold_days:
                    stale_invitations.append(member)

            if not stale_invitations:
                report.status = "PASS"
                report.status_extended = (
                    f"Team {team.name} has no stale pending invitations "
                    f"older than {stale_threshold_days} days."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Team {team.name} has {len(stale_invitations)} stale "
                    f"pending invitation(s) older than {stale_threshold_days} days."
                )

            findings.append(report)

        return findings
