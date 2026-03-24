"""ASPM-030: AI agent credentials must rotate at most every 90 days."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)

MAX_ROTATION_DAYS = 90


class aspm_agent_credential_rotation_enforced(Check):
    """Check that each AI agent rotates credentials at least every 90 days.

    Long-lived credentials increase the blast radius of a compromise.  Regular
    rotation limits exposure and is a foundational control required by CIS
    benchmarks, PCI-DSS, and most enterprise security policies.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            rotation = agent.credentials.rotation_interval_days
            if rotation is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no credential rotation policy configured."
                )
            elif rotation > MAX_ROTATION_DAYS:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} rotates credentials every {rotation} days, "
                    f"which exceeds the maximum allowed {MAX_ROTATION_DAYS} days."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} credentials rotate every {rotation} days."
                )
            findings.append(report)
        return findings
