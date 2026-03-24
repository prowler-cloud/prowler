"""ASPM-052: AI agent database queries must be fully audited."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_database_queries_audited(Check):
    """Check that database queries from the agent are fully audited.

    Without query audit logging, it is impossible to trace which data was
    accessed, by whom, and when — a critical requirement for forensics and
    regulatory compliance.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.data_access.database_query_audit_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} database queries are not audited "
                    "— cannot trace data access for forensics."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} database queries are fully audited with query text, identity, and result size."
            findings.append(report)
        return findings
