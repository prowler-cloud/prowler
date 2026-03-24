"""ASPM-078: AI agent must have anomaly detection monitoring enabled."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.observability.observability_client import (
    observability_client,
)


class aspm_agent_anomaly_detection_enabled(Check):
    """Check that AI agent anomaly detection monitoring is enabled.

    Without anomaly detection, compromised agent behaviour such as unusual tool
    usage patterns, excessive API calls, or unexpected data access goes
    undetected until significant damage has been done.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in observability_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.observability.anomaly_detection_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no anomaly detection — "
                    "compromised agent behaviour goes undetected."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has anomaly detection monitoring "
                    "for unusual behaviour."
                )
            findings.append(report)
        return findings
