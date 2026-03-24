"""ASPM-047: AI agents that access PII must have DLP controls enforced."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_pii_access_has_dlp(Check):
    """Check that AI agents accessing PII have Data Loss Prevention controls.

    When an agent can read or process Personally Identifiable Information
    it must be protected by DLP controls that prevent accidental or malicious
    exfiltration of that data.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if (
                agent.data_access.accesses_pii
                and not agent.data_access.has_dlp_controls
            ):
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} accesses PII without Data Loss Prevention controls."
            elif agent.data_access.accesses_pii:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} accesses PII with DLP controls enforced."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} does not access PII."
            findings.append(report)
        return findings
