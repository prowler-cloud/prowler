from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_meeting_presenters_restricted(Check):
    """Check if only organizers and co-organizers can present.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for meeting presenter settings.

        This method checks if only organizers and co-organizers can present.

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
                "Not only organizers and co-organizers can present."
            )

            if (
                global_meeting_policy.designated_presenter_role_mode
                == "OrganizerOnlyUserOverride"
            ):
                report.status = "PASS"
                report.status_extended = (
                    "Only organizers and co-organizers can present."
                )

            findings.append(report)

        return findings
