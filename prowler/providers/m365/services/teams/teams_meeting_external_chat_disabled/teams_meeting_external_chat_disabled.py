from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_meeting_external_chat_disabled(Check):
    """Check if external meeting chat is disabled.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for external meeting chat settings.

        This method checks if external meeting chat is disabled for untrusted organizations.

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
                "External meeting chat is enabled for untrusted organizations."
            )

            if not global_meeting_policy.allow_external_non_trusted_meeting_chat:
                report.status = "PASS"
                report.status_extended = (
                    "External meeting chat is disabled for untrusted organizations."
                )

            findings.append(report)

        return findings
