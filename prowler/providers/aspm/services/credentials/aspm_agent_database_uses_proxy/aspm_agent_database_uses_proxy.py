"""ASPM-032: AI agent database connections must use a managed proxy."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)


class aspm_agent_database_uses_proxy(Check):
    """Check that each AI agent uses a managed database proxy for database access.

    Managed proxies (RDS Proxy, Cloud SQL Proxy) eliminate the need for static
    database credentials in the application by brokering connections using
    IAM-based authentication.  This reduces the credential surface and enables
    connection pooling.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.credentials.database_uses_proxy:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} connects to databases without a managed proxy "
                    "— static credentials are in use."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} uses a managed database proxy for "
                    "credential-less database access."
                )
            findings.append(report)
        return findings
