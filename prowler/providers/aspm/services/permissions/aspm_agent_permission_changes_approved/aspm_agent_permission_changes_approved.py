"""ASPM-025: All AI agent permission changes must be traceable to approved change requests."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_permission_changes_approved(Check):
    """Check that all permission changes for AI agents are tied to approved requests.

    Unapproved permission changes indicate either a breakdown in the change
    management process or potential unauthorized access.  Every permission
    modification must be traceable to a ticket, pull request, or other
    auditable approval record to maintain compliance and accountability.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.permissions.permission_changes_approved:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has permission changes not traceable "
                    "to approved change requests."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} permission changes are traceable to "
                    "approved change requests."
                )
            findings.append(report)
        return findings
