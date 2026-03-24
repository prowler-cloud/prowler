"""ASPM-028: AI agent must retrieve credentials from a cloud secrets manager."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)


class aspm_agent_uses_secrets_manager(Check):
    """Check that each AI agent retrieves all credentials from a cloud secrets manager.

    Using a centralised secrets manager (AWS Secrets Manager, HashiCorp Vault,
    Azure Key Vault, GCP Secret Manager) eliminates static credential storage,
    enables automatic rotation, and provides a single audit point for credential
    access.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.credentials.uses_secrets_manager:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not use a cloud secrets manager "
                    "— credentials may be stored insecurely."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} retrieves all credentials from a cloud "
                    "secrets manager."
                )
            findings.append(report)
        return findings
