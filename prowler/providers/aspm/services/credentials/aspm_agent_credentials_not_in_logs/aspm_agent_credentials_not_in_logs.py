"""ASPM-027: AI agent credentials must not appear in logs."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)


class aspm_agent_credentials_not_in_logs(Check):
    """Check that each AI agent does not leak credentials into logs or error messages.

    Credentials appearing in logs are frequently collected by log aggregation
    systems and exposed to anyone with log access, far beyond the intended
    audience for the credential.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.credentials.credentials_in_logs:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} credentials are leaking into logs or "
                    "error messages."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} credentials do not appear in logs or "
                    "error messages."
                )
            findings.append(report)
        return findings
