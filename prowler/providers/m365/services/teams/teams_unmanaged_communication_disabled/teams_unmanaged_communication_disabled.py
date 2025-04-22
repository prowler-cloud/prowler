from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_unmanaged_communication_disabled(Check):
    """Check if unmanaged communication is disabled in Teams admin center.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for

        This method checks if unmanaged communication is disabled in Teams admin center.

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
            report.status_extended = "Users can communicate with unmanaged users."

            if user_settings and not user_settings.allow_teams_consumer:
                report.status = "PASS"
                report.status_extended = (
                    "Users can not communicate with unmanaged users."
                )

            findings.append(report)

        return findings
