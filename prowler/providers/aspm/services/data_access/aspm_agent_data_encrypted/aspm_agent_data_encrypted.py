"""ASPM-048: AI agent data must be encrypted at rest and in transit."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_data_encrypted(Check):
    """Check that all data accessed by the agent is encrypted at rest and in transit.

    Unencrypted data stores or unencrypted communication channels expose
    sensitive data to interception or direct access by unauthorised parties.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            missing = []
            if not agent.data_access.data_encrypted_at_rest:
                missing.append("at rest")
            if not agent.data_access.data_encrypted_in_transit:
                missing.append("in transit")
            if missing:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} data is not encrypted {' and '.join(missing)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} accesses only encrypted data (at rest and in transit)."
            findings.append(report)
        return findings
