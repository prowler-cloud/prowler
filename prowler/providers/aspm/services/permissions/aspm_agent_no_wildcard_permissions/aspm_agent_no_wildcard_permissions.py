"""ASPM-016: AI agent policies must not contain wildcard actions or resource ARNs."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_no_wildcard_permissions(Check):
    """Check that AI agent policies contain no wildcard actions or resource ARNs.

    Wildcard actions (``s3:*``, ``*:*``) and wildcard resource ARNs (``*``) in
    IAM policies grant far broader access than required.  Both dimensions must
    be restricted to specific actions on specific resources.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            has_wildcard_actions = agent.permissions.has_wildcard_actions
            has_wildcard_resources = agent.permissions.has_wildcard_resources
            if has_wildcard_actions or has_wildcard_resources:
                issues = []
                if has_wildcard_actions:
                    issues.append("wildcard actions")
                if has_wildcard_resources:
                    issues.append("wildcard resource ARNs")
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} policies contain "
                    f"{' and '.join(issues)} — least-privilege is violated."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} policies contain no wildcard "
                    "actions or resource ARNs."
                )
            findings.append(report)
        return findings
