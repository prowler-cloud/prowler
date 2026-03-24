"""ASPM-013: AI agent policies must not grant overprivileged access."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_permissions_no_overprivilege(Check):
    """Check that AI agent policies grant only specific, documented permissions.

    An agent is considered overprivileged when any attached policy contains
    wildcard actions (``s3:*``, ``*:*``) or an admin/power-user managed policy
    is attached.  Either condition means the agent can perform far more
    operations than its declared purpose requires.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if (
                agent.permissions.has_wildcard_actions
                or agent.permissions.has_admin_policy
            ):
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has overprivileged policies with "
                    "wildcard actions or admin access."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} policies grant only specific, "
                    "documented permissions."
                )
            findings.append(report)
        return findings
