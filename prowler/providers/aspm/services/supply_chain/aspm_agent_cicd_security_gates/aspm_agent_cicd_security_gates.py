"""ASPM-073: AI agent CI/CD pipeline must include security gates."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.supply_chain.supply_chain_client import (
    supply_chain_client,
)


class aspm_agent_cicd_security_gates(Check):
    """Check that each agent's CI/CD pipeline includes secret scanning, SAST, and dependency scanning."""

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in supply_chain_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.supply_chain.cicd_has_security_gates:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} CI/CD pipeline lacks security gates — vulnerable code can reach production."
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} CI/CD pipeline includes secret scanning, SAST, and dependency scanning."
            findings.append(report)
        return findings
