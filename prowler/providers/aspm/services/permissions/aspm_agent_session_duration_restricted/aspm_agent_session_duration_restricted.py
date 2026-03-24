"""ASPM-024: AI agent assumed-role sessions must not exceed 1 hour."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_session_duration_restricted(Check):
    """Check that AI agent assumed-role sessions are limited to 3600 seconds.

    Short-lived credentials reduce the window of opportunity for a stolen token
    to be exploited.  Sessions exceeding one hour (3600 seconds) or with no
    explicit limit increase the blast radius of a credential compromise, as the
    attacker retains access for longer without needing to re-authenticate.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            duration = agent.permissions.session_duration_seconds
            if duration is None or duration > 3600:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has unrestricted or overly long "
                    "session duration."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} assumed-role sessions are restricted "
                    "to 1 hour or less."
                )
            findings.append(report)
        return findings
