"""ASPM-051: AI agents must have a defined data retention policy."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_data_retention_policy(Check):
    """Check that the agent has a defined data retention policy with auto-purge.

    Without a retention policy, data may be kept indefinitely, increasing
    privacy risk and regulatory exposure under GDPR, CCPA, and similar laws.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            retention_days = agent.data_access.data_retention_policy_days
            if retention_days is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no data retention policy "
                    "— data may be retained indefinitely."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} has a {retention_days}-day data retention policy with auto-purge."
            findings.append(report)
        return findings
