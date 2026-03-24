"""ASPM-086: AI agent must have a performance baseline with deviation alerting."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.observability.observability_client import (
    observability_client,
)


class aspm_agent_performance_baseline_defined(Check):
    """Check that AI agent has a defined performance baseline with alerting.

    Without a performance baseline, gradual degradation that may indicate
    a compromised or resource-starved agent cannot be detected automatically.
    Significant deviation from baseline should trigger security alerts.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in observability_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.observability.performance_baseline_defined:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no performance baseline — "
                    "degradation indicating compromise is undetectable."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has a performance baseline defined with "
                    "alerting on significant deviation."
                )
            findings.append(report)
        return findings
