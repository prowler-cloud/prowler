"""ASPM-036: AI agent must use separate credentials per environment."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)


class aspm_agent_credentials_per_environment(Check):
    """Check that each AI agent uses separate credentials per environment.

    Shared credentials across dev, staging, and production environments mean
    that a compromise in a lower environment can directly impact production.
    Isolation reduces blast radius and simplifies revocation.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.credentials.credentials_per_environment:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} shares credentials across environments "
                    "— a dev credential compromise could affect prod."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} uses separate credentials per environment."
                )
            findings.append(report)
        return findings
