"""ASPM-042: AI agent API access must route through an authenticated API Gateway."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.network.network_client import network_client


class aspm_agent_api_gateway_enforced(Check):
    """Check that each AI agent routes all API access through an API Gateway.

    An agent is considered compliant when ``api_gateway_enforced`` is True.
    Direct backend API access bypasses centralised authentication, rate limiting,
    and audit logging provided by an API Gateway.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in network_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.network.api_gateway_enforced:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} backend APIs are accessible "
                    "without going through the API Gateway."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} all API access routes through "
                    "an authenticated API Gateway."
                )
            findings.append(report)
        return findings
