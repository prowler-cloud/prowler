from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.team.team_client import team_client


class team_saml_sso_enabled(Check):
    """Check if SAML SSO is enabled for the Vercel team.

    This class verifies whether the Vercel team has SAML single sign-on
    configured and enabled for centralized identity management.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Team SAML SSO Enabled check.

        Iterates over all teams and checks if SAML SSO is enabled.

        Returns:
            List[CheckReportVercel]: A list of reports for each team.
        """
        findings = []
        for team in team_client.teams.values():
            report = CheckReportVercel(
                metadata=self.metadata(),
                resource=team,
                resource_name=team.name,
                resource_id=team.id,
            )

            if team.saml and team.saml.status == "enabled":
                report.status = "PASS"
                report.status_extended = (
                    f"Team {team.name} has SAML SSO enabled"
                    f"{f' via {team.saml.provider}' if team.saml.provider else ''}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Team {team.name} does not have SAML SSO enabled. "
                    f"This feature is available on Vercel Enterprise and Pro plans."
                )

            findings.append(report)

        return findings
