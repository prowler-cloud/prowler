"""ASPM-034: AI agent credential access must be audited."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)


class aspm_agent_credential_access_audit_trail(Check):
    """Check that each AI agent logs and monitors credential access events.

    Without an audit trail for operations such as GetSecretValue, it is
    impossible to detect unauthorised credential retrieval or to reconstruct
    the sequence of events following a security incident.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.credentials.credential_access_audit_trail:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no audit trail for credential access "
                    "— cannot detect unauthorised retrieval."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} credential access (GetSecretValue, etc.) "
                    "is logged and monitored."
                )
            findings.append(report)
        return findings
