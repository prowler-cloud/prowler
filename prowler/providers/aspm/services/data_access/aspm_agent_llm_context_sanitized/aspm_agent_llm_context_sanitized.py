"""ASPM-054: AI agent LLM context windows must be sanitised of sensitive data."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_llm_context_sanitized(Check):
    """Check that the agent sanitises sensitive data before LLM context inclusion.

    Including credentials, PII, or other sensitive data in LLM context windows
    risks exposing that data to the model provider, prompt injection leakage,
    and logging in plaintext.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.data_access.llm_context_sanitized:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not sanitise its LLM context "
                    "— credentials and PII may be sent to the model."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} sanitises sensitive data before including it in LLM context windows."
            findings.append(report)
        return findings
