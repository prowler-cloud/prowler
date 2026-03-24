"""ASPM-049: AI agent cross-boundary data flows must be approved and documented."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_cross_boundary_flows_approved(Check):
    """Check that all cross-boundary data flows are whitelisted and documented.

    Data flows that cross trust boundaries (e.g., between accounts, regions,
    or third-party systems) must be explicitly approved and documented to
    prevent unauthorised data exfiltration.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.data_access.cross_boundary_data_flows_approved:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} has cross-boundary data flows that are not approved or documented."
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} cross-boundary data flows are whitelisted and documented."
            findings.append(report)
        return findings
