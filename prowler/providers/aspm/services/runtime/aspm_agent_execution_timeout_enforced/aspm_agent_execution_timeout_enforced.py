"""ASPM-064: AI agent must have execution time limits enforced."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.runtime.runtime_client import runtime_client


class aspm_agent_execution_timeout_enforced(Check):
    """Check that AI agents have execution timeouts configured.

    Agents without execution timeouts can run indefinitely, consuming CPU,
    memory, and downstream API quotas.  A runaway agent — whether due to
    an infinite loop, deadlock, or adversarial input — will remain active
    until the host is restarted or manually killed.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in runtime_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.runtime.has_execution_timeout:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no execution timeout — "
                    "runaway processes can consume resources indefinitely."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has execution time limits enforced."
                )
            findings.append(report)
        return findings
