"""ASPM-070: AI agent plugins and tools must be security-reviewed before deployment."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.supply_chain.supply_chain_client import (
    supply_chain_client,
)


class aspm_agent_plugins_security_reviewed(Check):
    """Check that each agent's plugins and tools have been security-reviewed before deployment."""

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in supply_chain_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.supply_chain.plugins_security_reviewed:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} plugins/tools have not been security-reviewed — unvalidated code execution risk."
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} plugins and tools have been security-reviewed before deployment."
            findings.append(report)
        return findings
