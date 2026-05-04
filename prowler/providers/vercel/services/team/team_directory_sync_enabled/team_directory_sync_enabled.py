from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.lib.billing import plan_reason_suffix
from prowler.providers.vercel.services.team.team_client import team_client


class team_directory_sync_enabled(Check):
    """Check if directory sync (SCIM) is enabled for the Vercel team.

    This class verifies whether the Vercel team has directory sync enabled,
    allowing automated user provisioning and deprovisioning through an
    identity provider.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Team Directory Sync Enabled check.

        Iterates over all teams and checks if directory sync is enabled.

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

            if team.directory_sync_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Team {team.name} has directory sync (SCIM) enabled "
                    f"for automated user provisioning."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Team {team.name} does not have directory sync (SCIM) enabled. "
                    f"User provisioning and deprovisioning must be managed manually."
                    f"{plan_reason_suffix(team.billing_plan, {'hobby', 'pro'}, 'directory sync (SCIM) is only available on Vercel Enterprise plans.')}"
                )

            findings.append(report)

        return findings
