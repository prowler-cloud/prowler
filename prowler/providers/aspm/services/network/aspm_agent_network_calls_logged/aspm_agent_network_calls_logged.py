"""ASPM-044: AI agent network calls must be logged with agent identity and destination."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.network.network_client import network_client


class aspm_agent_network_calls_logged(Check):
    """Check that each AI agent logs all network calls with agent identity and destination.

    An agent is considered compliant when ``network_calls_logged`` is True.
    Without network call logging, forensic analysis of agent activity is impossible
    after an incident.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in network_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.network.network_calls_logged:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} network calls are not logged — "
                    "cannot trace activity for forensics."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} network calls are logged "
                    "with agent identity and destination."
                )
            findings.append(report)
        return findings
