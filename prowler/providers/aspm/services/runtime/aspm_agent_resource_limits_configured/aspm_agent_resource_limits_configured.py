"""ASPM-059: AI agent container must have CPU, memory, and disk resource limits."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.runtime.runtime_client import runtime_client


class aspm_agent_resource_limits_configured(Check):
    """Check that every AI agent has resource limits configured.

    Agents without CPU, memory, and disk limits can starve adjacent workloads
    by consuming all available resources on shared infrastructure.  Resource
    limits also act as a DoS mitigation boundary.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in runtime_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.runtime.has_resource_limits:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no resource limits — "
                    "can exhaust shared infrastructure resources."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has CPU, memory, and disk limits configured."
                )
            findings.append(report)
        return findings
