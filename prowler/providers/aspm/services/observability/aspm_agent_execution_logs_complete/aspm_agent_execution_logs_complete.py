"""ASPM-077: AI agent execution logs must capture all actions and outputs."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.observability.observability_client import (
    observability_client,
)


class aspm_agent_execution_logs_complete(Check):
    """Check that AI agent execution logs are complete.

    Agents must capture all actions, tool invocations, decisions, and outputs
    in their execution logs to enable post-incident forensics.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in observability_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.observability.execution_logs_complete:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has incomplete execution logs — "
                    "post-incident forensics are not possible."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} execution logs capture all actions, "
                    "tool invocations, decisions, and outputs."
                )
            findings.append(report)
        return findings
