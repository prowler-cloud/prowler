"""ASPM-039: AI agent API endpoints must have rate limiting configured."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.network.network_client import network_client


class aspm_agent_rate_limiting_enabled(Check):
    """Check that each AI agent has rate limiting configured on its API endpoints.

    An agent is considered compliant when ``has_rate_limiting`` is True.
    Without rate limiting, burst calls from the agent or to the agent can exhaust
    downstream resources or facilitate denial-of-service conditions.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in network_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.network.has_rate_limiting:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} API endpoints have no rate limiting — "
                    "agent burst calls could exhaust resources."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} API endpoints have rate limiting configured."
                )
            findings.append(report)
        return findings
