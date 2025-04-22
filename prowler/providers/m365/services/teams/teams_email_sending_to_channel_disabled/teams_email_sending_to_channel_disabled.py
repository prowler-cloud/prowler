from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_email_sending_to_channel_disabled(Check):
    """Check if users can send emails to channel email addresses.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for

        This method checks if users can send emails to channel email addresses.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        teams_settings = teams_client.teams_settings
        if teams_settings:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=teams_settings if teams_settings else {},
                resource_name="Teams Settings",
                resource_id="teamsSettings",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Teams users can send emails to channel email addresses."
            )

            if teams_settings and not teams_settings.allow_email_into_channel:
                report.status = "PASS"
                report.status_extended = (
                    "Teams users cannot send emails to channel email addresses."
                )

            findings.append(report)

        return findings
