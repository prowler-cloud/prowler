from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_meeting_anonymous_user_join_disabled(Check):
    """Check if anonymous users are not able to join meetings.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for anonymous users are not able to join meetings.

        This method checks if anonymous users are not able to join meetings.

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
            report.status_extended = "Anonymous Teams users can join meetings."

            if not global_meeting_policy.allow_anonymous_users_to_join_meeting:
                report.status = "PASS"
                report.status_extended = "Anonymous Teams users can not join meetings."

            findings.append(report)

        return findings
