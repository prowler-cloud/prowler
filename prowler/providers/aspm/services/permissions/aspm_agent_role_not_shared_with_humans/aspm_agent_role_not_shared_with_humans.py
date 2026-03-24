"""ASPM-023: AI agent role must not be shared with human users."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_role_not_shared_with_humans(Check):
    """Check that AI agent roles are not shared with human identities.

    When a human and an agent share the same IAM role, CloudTrail logs cannot
    distinguish between human-initiated and agent-initiated actions.  This
    breaks non-repudiation, complicates incident response, and violates the
    principle of least-privilege identity separation.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.permissions.shares_role_with_human:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} shares its role with human users — "
                    "audit trail cannot distinguish actions."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} uses a dedicated role separate from "
                    "human identities."
                )
            findings.append(report)
        return findings
