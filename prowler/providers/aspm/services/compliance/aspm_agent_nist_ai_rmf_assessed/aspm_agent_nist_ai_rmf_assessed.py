"""ASPM-089: AI agent must be assessed against the NIST AI Risk Management Framework."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.compliance.compliance_client import (
    compliance_client,
)


class aspm_agent_nist_ai_rmf_assessed(Check):
    """Check that each AI agent has been assessed against the NIST AI RMF.

    The NIST AI Risk Management Framework (AI RMF 1.0) provides guidance to
    organisations for managing risks associated with AI systems across the
    entire AI lifecycle. Assessment against the framework demonstrates that
    governance, mapping, measurement, and management functions are in place.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in compliance_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.compliance.nist_ai_rmf_assessed:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has not been assessed against the NIST AI RMF."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has been assessed against the NIST AI Risk "
                    f"Management Framework."
                )
            findings.append(report)
        return findings
