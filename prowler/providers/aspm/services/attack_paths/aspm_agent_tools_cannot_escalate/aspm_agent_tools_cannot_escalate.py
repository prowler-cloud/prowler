"""ASPM-097: AI agent tools must not be abusable to escalate beyond the agent's declared permissions."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.attack_paths.attack_paths_client import (
    attack_paths_client,
)


class aspm_agent_tools_cannot_escalate(Check):
    """Check that AI agent tools cannot be chained or abused to exceed the agent's declared permissions.

    Agents are granted a set of tools (e.g., code-execution sandboxes, shell
    utilities, file-system accessors, API wrappers).  If those tools can be
    composed or abused — for example, through prompt injection, insecure
    deserialization, or SSRF — an attacker can achieve actions far beyond what
    the agent's IAM policy technically allows.  This check verifies that no
    such tool-abuse escalation path has been identified.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in attack_paths_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.attack_paths.tool_abuse_escalation_possible:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} tools can be chained or abused to escalate "
                    "beyond declared permissions."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} tools cannot be abused to exceed the agent's "
                    "declared permissions."
                )
            findings.append(report)
        return findings
