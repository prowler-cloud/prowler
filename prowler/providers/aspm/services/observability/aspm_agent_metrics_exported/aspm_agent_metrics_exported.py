"""ASPM-081: AI agent must export key operational metrics for monitoring."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.observability.observability_client import (
    observability_client,
)


class aspm_agent_metrics_exported(Check):
    """Check that AI agent exports key metrics for operational monitoring.

    Without exported metrics (latency, error rate, resource usage), operational
    anomalies that may indicate compromise or degradation cannot be detected
    by monitoring systems or security operations centres.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in observability_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.observability.metrics_exported:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not export metrics — operational "
                    "anomalies that indicate compromise go undetected."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} exports key metrics (latency, error rate, "
                    "resource usage) for monitoring."
                )
            findings.append(report)
        return findings
