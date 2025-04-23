from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_meeeting_external_lobby_bypass_disabled(Check):
    """Check if only people in the organization can bypass the lobby.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for only people in the organization can bypass the lobby.

        This method checks if only people in the organization can bypass the lobby.

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
            report.status_extended = (
                "People outside the organization can bypass the lobby."
            )

            if (
                global_meeting_policy.allow_external_users_to_bypass_lobby
                == "EveryoneInCompanyExcludingGuests"
            ):
                report.status = "PASS"
                report.status_extended = (
                    "Only people in the organization can bypass the lobby."
                )

            findings.append(report)

        return findings
