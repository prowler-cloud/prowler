"""ASPM-093: AI agent must have a tested, agent-specific incident response plan."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.compliance.compliance_client import (
    compliance_client,
)


class aspm_agent_incident_response_plan_exists(Check):
    """Check that each AI agent has a tested, agent-specific incident response plan.

    AI agents introduce novel failure modes including prompt injection, model
    misbehaviour, and autonomous action errors that may not be covered by generic
    IT incident response plans. An agent-specific plan ensures teams know how to
    contain, eradicate, and recover from agent-related incidents swiftly.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in compliance_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.compliance.incident_response_plan_exists:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no incident response plan — the organisation "
                    f"is unprepared for agent-related incidents."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} has a tested, agent-specific incident response plan."
            findings.append(report)
        return findings
