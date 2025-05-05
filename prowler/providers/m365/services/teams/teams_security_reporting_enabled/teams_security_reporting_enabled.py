from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_security_reporting_enabled(Check):
    """Check if users can report security concerns in Teams.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for Teams security reporting settings.

        This method checks if security reporting is properly configured in Teams settings.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        global_messaging_policy = teams_client.global_messaging_policy

        if global_messaging_policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=global_messaging_policy if global_messaging_policy else {},
                resource_name="Teams Security Reporting Settings",
                resource_id="teamsSecurityReporting",
            )

            teams_reporting_enabled = (
                global_messaging_policy.allow_security_end_user_reporting
            )

            if teams_reporting_enabled:
                report.status = "PASS"
                report.status_extended = (
                    "Security reporting is enabled in Teams messaging policy."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "Security reporting is not enabled in Teams messaging policy."
                )

            findings.append(report)

        return findings
