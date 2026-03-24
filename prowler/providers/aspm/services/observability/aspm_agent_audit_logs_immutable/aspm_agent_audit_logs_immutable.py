"""ASPM-080: AI agent audit logs must be immutable and integrity-protected."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.observability.observability_client import (
    observability_client,
)


class aspm_agent_audit_logs_immutable(Check):
    """Check that AI agent audit logs are immutable and integrity-protected.

    Mutable audit logs can be altered by an attacker after a breach to conceal
    their actions. Immutability ensures forensic evidence is preserved and
    tamper-evident.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in observability_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.observability.audit_logs_immutable:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} audit logs can be modified or deleted — "
                    "forensic evidence may be tampered with."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} audit logs are immutable, "
                    "integrity-protected, and centrally retained."
                )
            findings.append(report)
        return findings
