"""ASPM-041: AI agent must run in an isolated network segment."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.network.network_client import network_client


class aspm_agent_network_isolated(Check):
    """Check that each AI agent runs in an isolated network segment.

    An agent is considered compliant when ``network_isolated`` is True.
    Agents that share a network segment with unrelated workloads increase the
    blast radius of a compromise and enable lateral movement.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in network_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.network.network_isolated:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} is not isolated in its own network segment — "
                    "lateral movement risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} runs in an isolated network segment."
                )
            findings.append(report)
        return findings
