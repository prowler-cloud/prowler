"""ASPM-004: AI agent API keys must have a rotation policy of 90 days or less."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_api_key_rotation_policy(Check):
    """Check that each agent's API key rotation policy is ≤ 90 days and not exceeded.

    Three failure conditions are evaluated:
    - No rotation policy is defined.
    - The rotation policy window exceeds 90 days.
    - The current credential age exceeds 90 days (policy is violated in practice).
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            rotation_policy_days = agent.identity.rotation_policy_days
            credential_age_days = agent.identity.credential_age_days

            if rotation_policy_days is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no API key rotation policy defined."
                )
            elif rotation_policy_days > 90:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} rotation policy is {rotation_policy_days} days "
                    "— exceeds the 90-day maximum."
                )
            elif credential_age_days is not None and credential_age_days > 90:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} credentials are {credential_age_days} days old "
                    "— rotation policy has been violated."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} API keys rotate every {rotation_policy_days} days "
                    "and are within the rotation window."
                )
            findings.append(report)
        return findings
