"""ASPM-074: AI agent model and library licenses must be documented and compliant."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.supply_chain.supply_chain_client import (
    supply_chain_client,
)


class aspm_agent_license_compliance(Check):
    """Check that each agent's model and library licenses are documented and compliant."""

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in supply_chain_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.supply_chain.licenses_compliant:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} has license compliance issues — legal risk from GPL/AGPL or unlicensed components."
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} model and library licenses are documented and compliant."
            findings.append(report)
        return findings
