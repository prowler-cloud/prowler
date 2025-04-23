from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_external_domains_restricted(Check):
    """Check if external domains are restricted from being used in Teams admin center.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for

        This method checks if external domains are restricted from being used in Teams admin center.

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
            report.status_extended = "Users can access external domains."

            if user_settings and not user_settings.allow_external_access:
                report.status = "PASS"
                report.status_extended = "Users can not access external domains."

            findings.append(report)

        return findings
