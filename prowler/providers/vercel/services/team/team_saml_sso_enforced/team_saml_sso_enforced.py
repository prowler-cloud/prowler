from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.team.team_client import team_client


class team_saml_sso_enforced(Check):
    """Check if SAML SSO enforcement is enabled for the Vercel team.

    This class verifies whether the Vercel team enforces SAML SSO,
    requiring all members to authenticate through the identity provider.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Team SAML SSO Enforced check.

        Iterates over all teams and checks if SAML SSO is enforced.

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

            if team.saml and team.saml.enforced:
                report.status = "PASS"
                report.status_extended = (
                    f"Team {team.name} enforces SAML SSO for all members."
                )
            else:
                report.status = "FAIL"
                if team.saml and team.saml.status == "enabled":
                    report.status_extended = (
                        f"Team {team.name} has SAML SSO enabled but does not enforce it. "
                        f"Members can still authenticate without SSO. This feature is "
                        f"available on Vercel Enterprise and Pro plans."
                    )
                else:
                    report.status_extended = (
                        f"Team {team.name} does not have SAML SSO enforced. "
                        f"This feature is available on Vercel Enterprise and Pro plans."
                    )

            findings.append(report)

        return findings
