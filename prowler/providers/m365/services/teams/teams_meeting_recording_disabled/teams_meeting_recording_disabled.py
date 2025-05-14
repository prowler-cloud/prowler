from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_meeting_recording_disabled(Check):
    """Check if meeting recording is disabled by default.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for meeting recording settings.

        This method checks if meeting recording is disabled in the Global meeting policy.

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
            report.status_extended = "Meeting recording is enabled by default."

            if not global_meeting_policy.allow_cloud_recording:
                report.status = "PASS"
                report.status_extended = "Meeting recording is disabled by default."

            findings.append(report)

        return findings
