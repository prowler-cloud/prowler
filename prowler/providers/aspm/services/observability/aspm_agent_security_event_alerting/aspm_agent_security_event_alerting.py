"""ASPM-082: AI agent security events must trigger alerts within 5 minutes."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.observability.observability_client import (
    observability_client,
)


class aspm_agent_security_event_alerting(Check):
    """Check that AI agent security events trigger timely alerts.

    Without automated alerting on security events, incidents may go unnoticed
    for extended periods, significantly increasing the blast radius of any
    breach or misuse.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in observability_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.observability.security_event_alerting:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no security event alerting — "
                    "incidents may go unnoticed for extended periods."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} security events trigger alerts "
                    "within 5 minutes."
                )
            findings.append(report)
        return findings
