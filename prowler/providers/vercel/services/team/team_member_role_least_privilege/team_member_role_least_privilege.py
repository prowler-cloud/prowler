from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.team.team_client import team_client


class team_member_role_least_privilege(Check):
    """Check if the Vercel team follows least privilege for owner roles.

    This class verifies that the percentage of team members with the OWNER
    role does not exceed 20% of total active members, following the
    principle of least privilege.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Team Member Role Least Privilege check.

        Iterates over all teams and checks if the proportion of OWNER
        members is within acceptable bounds.

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

            active_members = [m for m in team.members if m.status == "active"]
            total_active = len(active_members)

            if total_active == 0:
                report.status = "PASS"
                report.status_extended = (
                    f"Team {team.name} has no active members to evaluate."
                )
                findings.append(report)
                continue

            owners = [m for m in active_members if m.role == "OWNER"]
            owner_count = len(owners)
            owner_percentage = (owner_count / total_active) * 100

            if total_active < 5 and owner_count <= 1:
                report.status = "PASS"
                report.status_extended = (
                    f"Team {team.name} has {owner_count} owner(s) out of "
                    f"{total_active} active members. Small team with minimum "
                    f"required owner — least privilege threshold not applicable."
                )
            elif owner_percentage <= 20:
                report.status = "PASS"
                report.status_extended = (
                    f"Team {team.name} has {owner_count} owner(s) out of "
                    f"{total_active} active members ({owner_percentage:.0f}%), "
                    f"which is within the recommended 20% threshold."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Team {team.name} has {owner_count} owner(s) out of "
                    f"{total_active} active members ({owner_percentage:.0f}%), "
                    f"which exceeds the recommended 20% threshold."
                )

            findings.append(report)

        return findings
