"""ASPM-021: AI agent service principals must carry all required governance tags."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_identity_fully_tagged(Check):
    """Check that AI agent service principals have all required governance tags.

    Governance tags (e.g. ``owner``, ``environment``, ``data-classification``,
    ``cost-centre``) on IAM roles and service accounts enable automated policy
    enforcement, cost attribution, and access-control via attribute-based access
    control (ABAC).  Missing tags break these controls.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.permissions.all_resources_tagged:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} service principals are missing "
                    "required governance tags."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} service principals carry all "
                    "required governance tags."
                )
            findings.append(report)
        return findings
