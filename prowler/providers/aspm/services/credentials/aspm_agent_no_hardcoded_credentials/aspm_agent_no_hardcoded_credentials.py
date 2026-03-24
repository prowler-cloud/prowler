"""ASPM-026: AI agent must not have hardcoded credentials."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)


class aspm_agent_no_hardcoded_credentials(Check):
    """Check that each AI agent has no hardcoded credentials in code, IaC, or manifests.

    Hardcoded credentials are a critical security risk because they cannot be
    rotated without code changes and are frequently exposed via version control
    history, container images, or log output.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.credentials.has_hardcoded_secrets:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has hardcoded secrets detected in code, "
                    "deployment manifests, or IaC."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has no hardcoded credentials in code, "
                    "IaC, or manifests."
                )
            findings.append(report)
        return findings
