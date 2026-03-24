"""ASPM-068: AI agent frameworks must be scanned for CVEs."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.supply_chain.supply_chain_client import (
    supply_chain_client,
)


class aspm_agent_framework_cves_scanned(Check):
    """Check that each agent's frameworks (LangChain, LlamaIndex, etc.) are scanned for CVEs."""

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in supply_chain_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.supply_chain.framework_cves_scanned:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} agent frameworks are not scanned for known vulnerabilities."
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} frameworks (LangChain, LlamaIndex, etc.) are scanned for CVEs."
            findings.append(report)
        return findings
