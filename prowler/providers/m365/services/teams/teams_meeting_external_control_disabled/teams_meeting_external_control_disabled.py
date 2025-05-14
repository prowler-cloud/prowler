from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_meeting_external_control_disabled(Check):
    """Check if external participants can't give or request control in meetings.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for external participants' control permissions in meetings.

        This method checks if external participants are prevented from giving or requesting control in meetings.

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
                "External participants can give or request control."
            )

            if (
                not global_meeting_policy.allow_external_participant_give_request_control
            ):
                report.status = "PASS"
                report.status_extended = (
                    "External participants cannot give or request control."
                )

            findings.append(report)

        return findings
