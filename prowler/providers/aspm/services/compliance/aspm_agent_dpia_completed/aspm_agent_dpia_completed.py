"""ASPM-091: AI agent must have a completed Data Privacy Impact Assessment (DPIA)."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.compliance.compliance_client import (
    compliance_client,
)


class aspm_agent_dpia_completed(Check):
    """Check that each AI agent has a completed Data Privacy Impact Assessment.

    A DPIA is mandatory under GDPR Article 35 for high-risk processing activities
    and strongly recommended under CCPA and other privacy regulations. It identifies
    privacy risks, documents mitigations, and demonstrates accountability to
    supervisory authorities. Failure to complete a DPIA exposes organisations to
    significant regulatory fines and reputational damage.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in compliance_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.compliance.dpia_completed:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} processes personal data without a DPIA — "
                    f"GDPR/CCPA compliance risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} has a completed Data Privacy Impact Assessment."
            findings.append(report)
        return findings
