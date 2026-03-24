"""ASPM-017: AI agent cross-account access must not exceed 3 accounts."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_cross_account_access_restricted(Check):
    """Check that AI agent cross-account access is limited to at most 3 accounts.

    Cross-account access significantly expands the blast radius of a compromised
    agent.  When an agent has cross-account trust relationships with more than
    three accounts, the access is considered unrestricted and must be reviewed
    and scoped down.
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
                agent.permissions.cross_account_access
                and agent.permissions.cross_account_accounts > 3
            ):
                count = agent.permissions.cross_account_accounts
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has cross-account access to "
                    f"{count} accounts — exceeds the maximum of 3."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has no unrestricted cross-account access."
                )
            findings.append(report)
        return findings
