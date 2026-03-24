"""ASPM-088: AI agent must have EU AI Act compliance controls documented."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.compliance.compliance_client import (
    compliance_client,
)


class aspm_agent_eu_ai_act_controls(Check):
    """Check that each AI agent has EU AI Act compliance controls documented.

    The EU AI Act imposes requirements on high-risk AI systems deployed in the
    European Union, including transparency obligations, human oversight mechanisms,
    and risk management systems. Agents without documented controls face regulatory
    penalties and potential enforcement action.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in compliance_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.compliance.eu_ai_act_controls_present:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} lacks EU AI Act compliance controls — "
                    f"regulatory risk for EU-deployed agents."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has EU AI Act compliance controls documented."
                )
            findings.append(report)
        return findings
