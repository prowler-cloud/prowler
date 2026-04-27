"""ASPM-020: AI agent must access only a single data domain."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_single_data_domain_access(Check):
    """Check that AI agents are scoped to a single data domain.

    An agent accessing multiple data domains (e.g. both S3 and RDS and
    Redshift) has a wider blast radius than necessary.  Scope creep across data
    domains increases the impact of a prompt-injection or supply-chain attack
    and complicates data-lineage governance.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            domains = agent.permissions.data_domains_accessed
            if len(domains) > 1:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} accesses multiple data domains "
                    f"({', '.join(domains)}) — potential scope creep."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} accesses a single data domain " "as expected."
                )
            findings.append(report)
        return findings
