"""ASPM-071: AI agent dependencies must use exact pinned versions with lock files."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.supply_chain.supply_chain_client import (
    supply_chain_client,
)


class aspm_agent_dependencies_version_pinned(Check):
    """Check that each agent's dependencies use exact pinned versions with lock files."""

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in supply_chain_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.supply_chain.dependencies_version_pinned:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} uses floating dependency versions — non-reproducible builds and supply chain risk."
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} all dependencies use exact pinned versions with lock files."
            findings.append(report)
        return findings
