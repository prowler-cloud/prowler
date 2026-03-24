"""ASPM-101: AI agent must not execute LLM output directly in system calls or eval()."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.attack_paths.attack_paths_client import (
    attack_paths_client,
)


class aspm_agent_llm_output_not_executed(Check):
    """Check that AI agents do not execute LLM output directly in system calls or eval().

    When an agent passes raw LLM-generated text to system calls, eval(),
    exec(), subprocess.run(shell=True), or equivalent code-execution
    primitives without sanitisation and allow-listing, an adversary who
    controls any part of the LLM's prompt — through prompt injection, a
    poisoned document, or a malicious tool response — can achieve Remote Code
    Execution (RCE) on the agent host with the agent's privileges.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in attack_paths_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.attack_paths.llm_output_used_in_code_execution:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} uses LLM output directly in code execution — "
                    "prompt injection can achieve RCE."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} does not execute LLM output directly in "
                    "system calls or eval()."
                )
            findings.append(report)
        return findings
