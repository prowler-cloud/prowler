"""ASPM-018: AI agent permissions must be reviewed within the past 90 days."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_permissions_recently_reviewed(Check):
    """Check that AI agent permissions were reviewed within the last 90 days.

    Permissions that have never been reviewed or were last reviewed more than
    90 days ago are likely to contain privilege creep — incremental grants
    that accumulate over time.  Regular review cycles ensure that permissions
    remain aligned with the agent's current operating requirements.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            days = agent.permissions.permissions_last_reviewed_days
            if days is None or days > 90:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} permissions have not been reviewed recently."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} permissions were reviewed within "
                    "the past 90 days."
                )
            findings.append(report)
        return findings
