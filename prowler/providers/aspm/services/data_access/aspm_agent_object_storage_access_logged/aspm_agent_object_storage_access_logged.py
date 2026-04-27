"""ASPM-053: AI agent object storage access must be logged."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_object_storage_access_logged(Check):
    """Check that object storage access is logged with agent identity.

    Object storage (S3, Azure Blob, GCS) is a common target for data
    exfiltration. Without access logs, GET/PUT/DELETE operations by the
    agent cannot be audited.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.data_access.object_storage_access_logged:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} object storage operations are not logged "
                    "— cannot audit data access."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} object storage access (GET/PUT/DELETE) is logged with agent identity."
            findings.append(report)
        return findings
