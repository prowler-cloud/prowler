"""ASPM-079: AI agent LLM inputs must be monitored for prompt injection."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.observability.observability_client import (
    observability_client,
)


class aspm_agent_prompt_injection_monitoring(Check):
    """Check that AI agent LLM inputs are monitored for prompt injection.

    Prompt injection and jailbreak attacks can redirect an agent to perform
    unauthorised actions. Monitoring LLM inputs enables detection and
    blocking of such attempts before they cause harm.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in observability_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.observability.prompt_injection_monitoring:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no monitoring for prompt injection — "
                    "malicious prompts go undetected."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} LLM inputs are monitored for prompt "
                    "injection and jailbreak attempts."
                )
            findings.append(report)
        return findings
