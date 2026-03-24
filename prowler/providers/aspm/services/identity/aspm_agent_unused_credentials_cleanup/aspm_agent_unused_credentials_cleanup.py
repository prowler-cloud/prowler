"""ASPM-012: AI agent must not have unused secondary credentials."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_unused_credentials_cleanup(Check):
    """Check that each AI agent has no unused secondary credentials.

    Unused backup API keys, secondary access keys, or additional service
    account tokens represent latent attack surface.  They may be forgotten
    and never rotated, providing a persistent foothold for attackers.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.identity.unused_secondary_credentials:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has unused secondary credentials "
                    "that should be deprovisioned."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has no unused secondary credentials."
                )
            findings.append(report)
        return findings
