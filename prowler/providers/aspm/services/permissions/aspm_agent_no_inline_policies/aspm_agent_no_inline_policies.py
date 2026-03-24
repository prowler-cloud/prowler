"""ASPM-014: AI agent roles must not use inline policies."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_no_inline_policies(Check):
    """Check that AI agent roles rely solely on managed policies.

    Inline policies are embedded directly in an IAM identity and do not appear
    in the AWS managed-policy inventory.  They bypass standard policy-versioning
    and approval workflows, making them harder to audit and roll back.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.permissions.has_inline_policies:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has inline policies which bypass "
                    "versioning and approval workflows."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} uses only managed policies — "
                    "no inline policies detected."
                )
            findings.append(report)
        return findings
