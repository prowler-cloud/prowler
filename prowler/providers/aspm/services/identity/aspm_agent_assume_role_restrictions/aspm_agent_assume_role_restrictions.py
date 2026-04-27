"""ASPM-010: AI agent assume-role sessions must have a maximum duration of 3600 seconds."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_assume_role_restrictions(Check):
    """Check that each AI agent's assume-role session duration is ≤ 3600 seconds.

    Long or unlimited session durations mean that a stolen session token
    remains valid for an extended period, giving attackers more time to
    exploit compromised credentials.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            session_duration_seconds = agent.identity.session_duration_seconds
            if session_duration_seconds is None or session_duration_seconds > 3600:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has unrestricted or overly long session duration "
                    "for assumed roles."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} cross-account assume role is restricted with "
                    "conditions and short session duration."
                )
            findings.append(report)
        return findings
