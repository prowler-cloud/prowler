"""ASPM-006: AI agent must validate JWT claims on all agent-to-agent calls."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_jwt_claims_validation(Check):
    """Check that each AI agent validates JWT claims (exp, iss, sub, aud).

    Skipping JWT claim validation allows expired or cross-audience tokens to
    be accepted, enabling token replay and confused-deputy attacks across
    agent-to-agent communication channels.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.identity.jwt_validation_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not validate JWT claims — "
                    "agent-to-agent communication is vulnerable to token abuse."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} validates JWT claims (exp, iss, sub, aud) "
                    "on all agent-to-agent calls."
                )
            findings.append(report)
        return findings
