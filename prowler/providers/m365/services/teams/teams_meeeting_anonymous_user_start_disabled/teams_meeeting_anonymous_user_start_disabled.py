from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_meeeting_anonymous_user_start_disabled(Check):
    """Check if anonymous users are not able to start meetings.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for anonymous users are not able to start meetings.

        This method checks if anonymous users and dial-in callers are not able to start meetings.

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
            report.status_extended = "Anonymous Teams users can start meetings."

            if (
                global_meeting_policy
                and not global_meeting_policy.allow_anonymous_users_to_start_meeting
            ):
                report.status = "PASS"
                report.status_extended = "Anonymous Teams users can not start meetings."

            findings.append(report)

        return findings
