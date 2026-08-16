from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_external_access_trial_tenants_blocked(Check):
    """Check if external access with Teams trial-only tenants is blocked.

    This setting controls external access with Teams "trial-only" tenants (tenants
    that don't have any purchased seats). When blocked, users from those tenants
    cannot search for, chat, call, or meet with the organization's users.

    - PASS: External access with trial-only tenants is blocked.
    - FAIL: External access with trial-only tenants is allowed.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for external access with trial-only Teams tenants.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        user_settings = teams_client.user_settings
        if user_settings:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=user_settings,
                resource_name="Teams User Settings",
                resource_id="userSettings",
            )
            report.status = "FAIL"
            report.status_extended = (
                "External access with Teams trial-only tenants is allowed."
            )

            if user_settings.external_access_with_trial_tenants == "Blocked":
                report.status = "PASS"
                report.status_extended = (
                    "External access with Teams trial-only tenants is blocked."
                )

            findings.append(report)

        return findings
