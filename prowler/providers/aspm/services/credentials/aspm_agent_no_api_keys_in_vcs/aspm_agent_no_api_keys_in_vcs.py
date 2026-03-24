"""ASPM-029: AI agent must not have API keys or tokens committed to version control."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)


class aspm_agent_no_api_keys_in_vcs(Check):
    """Check that each AI agent has no API keys or tokens in version control history.

    Secrets committed to VCS persist in repository history even after removal.
    Attackers routinely scan public and leaked repositories for credentials
    using automated tooling.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.credentials.api_key_in_vcs:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has API keys or tokens found in version "
                    "control history."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has no API keys or tokens committed to "
                    "version control."
                )
            findings.append(report)
        return findings
