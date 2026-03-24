"""ASPM-001: AI agent identity must be tagged and inventoried."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_identity_tagged_and_inventoried(Check):
    """Check that each AI agent identity has required tags and is inventoried.

    An agent identity is considered compliant when it has at least one tag
    applied AND the ``has_owner_tag`` field is True.  Missing tags prevent
    attribution, auditability, and cost allocation.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.identity.tags or not agent.identity.has_owner_tag:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} is missing required identity tags "
                    "(agent, owner, purpose)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has a complete identity inventory "
                    "with required tags."
                )
            findings.append(report)
        return findings
