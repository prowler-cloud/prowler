from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_meeting_chat_anonymous_users_disabled(Check):
    """Check if meeting chat does not allow anonymous users.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for meeting chat does not allow anonymous users.

        This method checks if meeting chat does not allow anonymous users.

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
            report.status_extended = "Meeting chat allows anonymous users."

            allowed_meeting_chat_settings = {
                "EnabledExceptAnonymous",
                "EnabledInMeetingOnlyForAllExceptAnonymous",
            }

            if (
                global_meeting_policy.meeting_chat_enabled_type
                in allowed_meeting_chat_settings
            ):
                report.status = "PASS"
                report.status_extended = "Meeting chat does not allow anonymous users."

            findings.append(report)

        return findings
