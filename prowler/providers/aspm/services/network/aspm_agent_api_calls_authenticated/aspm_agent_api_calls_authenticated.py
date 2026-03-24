"""ASPM-038: AI agent internal API calls must be authenticated."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.network.network_client import network_client


class aspm_agent_api_calls_authenticated(Check):
    """Check that each AI agent requires authentication on all internal API calls.

    An agent is considered compliant when ``api_calls_authenticated`` is True.
    Unauthenticated API calls allow any caller on the network to invoke agent
    endpoints without proving their identity.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in network_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.network.api_calls_authenticated:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} makes unauthenticated API calls — "
                    "request identity cannot be verified."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} requires authentication "
                    "on all internal API calls."
                )
            findings.append(report)
        return findings
