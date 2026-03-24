"""ASPM-075: AI agent LLM model must receive security updates within 30 days."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.supply_chain.supply_chain_client import (
    supply_chain_client,
)


class aspm_agent_model_update_cadence(Check):
    """Check that each agent's LLM model update cadence is defined and does not exceed 30 days."""

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in supply_chain_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            cadence = agent.supply_chain.model_update_cadence_days
            if cadence is None or cadence > 30:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} LLM model update cadence is not defined or exceeds 30 days."
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} LLM model receives security updates within {cadence} days."
            findings.append(report)
        return findings
