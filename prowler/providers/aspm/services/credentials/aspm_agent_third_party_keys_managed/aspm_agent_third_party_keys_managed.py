"""ASPM-033: AI agent third-party API keys must be managed in a secrets manager."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)


class aspm_agent_third_party_keys_managed(Check):
    """Check that each AI agent stores third-party API keys in a secrets manager.

    Third-party API keys (Slack, GitHub, OpenAI, etc.) have the same risk profile
    as cloud credentials.  Storing them in a secrets manager with rotation
    prevents sprawl and enables rapid revocation if compromised.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.credentials.third_party_keys_managed:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} third-party API keys are not managed "
                    "through a secrets manager."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} third-party API keys are stored in a "
                    "secrets manager with rotation."
                )
            findings.append(report)
        return findings
