"""ASPM-015: AI agent must not have privilege escalation paths to human admin roles."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_no_privilege_escalation_path(Check):
    """Check that AI agents cannot escalate privileges to human admin roles.

    Privilege escalation paths (e.g. ``iam:PassRole``, ``sts:AssumeRole`` to
    admin roles) allow a compromised agent to gain human-administrator-level
    access.  This is a critical risk because it breaks the separation between
    automated and human trust boundaries.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.permissions.can_escalate_privileges:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} can escalate privileges to human "
                    "admin roles — critical risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has no privilege escalation paths "
                    "to human admin roles."
                )
            findings.append(report)
        return findings
