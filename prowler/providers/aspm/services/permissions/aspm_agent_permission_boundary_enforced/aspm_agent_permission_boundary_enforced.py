"""ASPM-022: AI agent IAM role must have a permission boundary enforced."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_permission_boundary_enforced(Check):
    """Check that AI agent IAM roles have a permission boundary attached.

    A permission boundary is a managed policy that caps the maximum permissions
    an IAM entity can have, regardless of any other policies attached to it.
    Without a boundary, a misconfigured or malicious policy addition could
    escalate the agent's effective permissions to the full policy set.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.permissions.has_permission_boundary:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no permission boundary — "
                    "escalation to maximum permissions is possible."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has a permission boundary enforcing "
                    "the maximum permission set."
                )
            findings.append(report)
        return findings
