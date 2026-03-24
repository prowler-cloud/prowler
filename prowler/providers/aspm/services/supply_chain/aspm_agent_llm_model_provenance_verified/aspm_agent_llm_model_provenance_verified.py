"""ASPM-069: AI agent LLM model provenance must be verified."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.supply_chain.supply_chain_client import (
    supply_chain_client,
)


class aspm_agent_llm_model_provenance_verified(Check):
    """Check that each agent's LLM model provenance is verified with checksums and a trusted source."""

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in supply_chain_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.supply_chain.llm_model_provenance_verified:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} LLM model has no provenance verification — model substitution/poisoning risk."
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} LLM model provenance is verified with checksums and trusted source."
            findings.append(report)
        return findings
