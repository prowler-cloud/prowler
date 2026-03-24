"""ASPM-063: AI agent must clear sensitive data from memory after use."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.runtime.runtime_client import runtime_client


class aspm_agent_secrets_cleared_from_memory(Check):
    """Check that AI agents clear secrets and sensitive data from memory after use.

    Credentials and tokens left in memory can be extracted via memory dump
    attacks, core dumps, or debugging interfaces.  Explicitly zeroing or
    replacing secret buffers after use reduces the window of exposure.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in runtime_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.runtime.secrets_cleared_from_memory:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not clear secrets from memory — "
                    "credentials may be exposed via memory dumps."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} clears sensitive data from memory after use."
                )
            findings.append(report)
        return findings
