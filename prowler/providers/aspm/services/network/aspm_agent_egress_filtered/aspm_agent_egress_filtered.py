"""ASPM-040: AI agent outbound network access must be filtered by destination."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.network.network_client import network_client


class aspm_agent_egress_filtered(Check):
    """Check that each AI agent has egress filtering applied to outbound network access.

    An agent is considered compliant when ``has_egress_filtering`` is True.
    Unrestricted outbound access allows a compromised or prompt-injected agent to
    exfiltrate data to arbitrary external destinations.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in network_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.network.has_egress_filtering:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has unrestricted outbound network access — "
                    "data exfiltration path exists."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} outbound network access is filtered by destination."
            findings.append(report)
        return findings
