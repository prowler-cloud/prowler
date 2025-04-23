from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_meeting_dial_in_lobby_bypass_disabled(Check):
    """Check if users dialing in can't bypass the lobby.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for users dialing in can't bypass the lobby.

        This method checks if users dialing in can't bypass the lobby.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        global_meeting_policy = teams_client.global_meeting_policy
        if global_meeting_policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=global_meeting_policy if global_meeting_policy else {},
                resource_name="Teams Meetings Global (Org-wide default) Policy",
                resource_id="teamsMeetingsGlobalPolicy",
            )
            report.status = "FAIL"
            report.status_extended = "Users dialing in can bypass the lobby."

            if not global_meeting_policy.allow_pstn_users_to_bypass_lobby:
                report.status = "PASS"
                report.status_extended = "Users dialing in can't bypass the lobby."

            findings.append(report)

        return findings
