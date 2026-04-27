"""ASPM-084: AI agent must be visible in a centralised security posture dashboard."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.observability.observability_client import (
    observability_client,
)


class aspm_agent_centralized_dashboard(Check):
    """Check that AI agent is visible in a centralised security posture dashboard.

    Agents not represented in a centralised dashboard require manual tracking
    of security posture, increasing the risk of oversight and delayed detection
    of security issues across the agent fleet.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in observability_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.observability.centralized_dashboard:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} is not visible in a centralised dashboard — "
                    "security posture is manually tracked."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} is visible in a centralised security "
                    "posture dashboard."
                )
            findings.append(report)
        return findings
