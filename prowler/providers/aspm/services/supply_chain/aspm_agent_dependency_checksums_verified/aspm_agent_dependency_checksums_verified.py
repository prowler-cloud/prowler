"""ASPM-076: AI agent package checksums must be verified on every dependency download."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.supply_chain.supply_chain_client import (
    supply_chain_client,
)


class aspm_agent_dependency_checksums_verified(Check):
    """Check that each agent's package checksums/signatures are verified on every dependency download."""

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in supply_chain_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.supply_chain.dependency_checksums_verified:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} downloads dependencies without checksum verification — typosquatting/hijack risk."
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} package checksums/signatures are verified on every dependency download."
            findings.append(report)
        return findings
