"""ASPM-083: AI agent must propagate W3C trace context for distributed tracing."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.observability.observability_client import (
    observability_client,
)


class aspm_agent_distributed_tracing_enabled(Check):
    """Check that AI agent uses distributed tracing across all service calls.

    Without distributed tracing, it is impossible to reconstruct multi-agent
    incident timelines. W3C trace context propagation enables end-to-end
    visibility across all services involved in a request chain.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in observability_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.observability.distributed_tracing_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not use distributed tracing — "
                    "cannot trace multi-agent incident timelines."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} propagates W3C trace context across "
                    "all service calls."
                )
            findings.append(report)
        return findings
