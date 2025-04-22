from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_external_users_cannot_start_conversations(Check):
    """Check if external users cannot start conversations.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for external users cannot start conversations.

        This method checks if external users cannot start conversations.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        user_settings = teams_client.user_settings
        if user_settings:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=user_settings if user_settings else {},
                resource_name="Teams User Settings",
                resource_id="userSettings",
            )
            report.status = "FAIL"
            report.status_extended = "External Teams users can initiate conversations."

            if user_settings and not user_settings.allow_teams_consumer_inbound:
                report.status = "PASS"
                report.status_extended = (
                    "External Teams users cannot initiate conversations."
                )

            findings.append(report)

        return findings
