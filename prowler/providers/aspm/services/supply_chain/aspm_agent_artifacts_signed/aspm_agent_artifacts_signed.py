"""ASPM-072: AI agent container images and artifacts must be cryptographically signed."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.supply_chain.supply_chain_client import (
    supply_chain_client,
)


class aspm_agent_artifacts_signed(Check):
    """Check that each agent's container images and artifacts are cryptographically signed (cosign/SLSA)."""

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in supply_chain_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.supply_chain.artifacts_signed:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} artifacts are not signed — cannot verify authenticity before deployment."
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} container images and artifacts are cryptographically signed (cosign/SLSA)."
            findings.append(report)
        return findings
