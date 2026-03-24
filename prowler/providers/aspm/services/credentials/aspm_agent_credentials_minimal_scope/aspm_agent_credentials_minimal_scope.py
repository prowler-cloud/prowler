"""ASPM-035: AI agent credentials must be scoped to minimum required permissions."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)


class aspm_agent_credentials_minimal_scope(Check):
    """Check that each AI agent uses credentials scoped to the minimum required permissions.

    Over-privileged credentials amplify the impact of a compromise.  Credentials
    should follow the principle of least privilege: grant only the permissions
    required for the specific tasks the agent performs.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.credentials.credentials_scoped:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} credentials have excessive scope "
                    "— should be restricted to minimum required."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} credentials are scoped to the minimum "
                    "required permissions."
                )
            findings.append(report)
        return findings
