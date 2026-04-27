"""ASPM-007: AI agent credentials must not exceed 365 days of age."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_credential_age(Check):
    """Check that each AI agent's credentials are not older than 365 days.

    Credentials older than one year represent a significant risk: they have
    had a longer window of potential exposure and may have been shared,
    logged, or exfiltrated without detection.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            credential_age_days = agent.identity.credential_age_days
            if credential_age_days is not None and credential_age_days > 365:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} credentials are {credential_age_days} days old "
                    "— exceeds the 365-day maximum."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} credentials are within the maximum allowed age."
            findings.append(report)
        return findings
