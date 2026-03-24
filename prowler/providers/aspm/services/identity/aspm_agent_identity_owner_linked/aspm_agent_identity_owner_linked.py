"""ASPM-009: AI agent identity must be linked to a documented owner team."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_identity_owner_linked(Check):
    """Check that each AI agent identity has an owner tag linking it to a team.

    Without owner attribution, no team is accountable for the agent's security
    posture, permission reviews, or incident response, leading to governance
    gaps in the identity lifecycle.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.identity.has_owner_tag:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} identity has no owner tag "
                    "— cannot be attributed to a team."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} identity is linked to a documented owner team."
                )
            findings.append(report)
        return findings
