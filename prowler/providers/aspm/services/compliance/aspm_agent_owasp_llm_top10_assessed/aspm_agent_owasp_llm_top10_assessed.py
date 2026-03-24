"""ASPM-087: AI agent must be assessed against the OWASP LLM Top 10."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.compliance.compliance_client import (
    compliance_client,
)


class aspm_agent_owasp_llm_top10_assessed(Check):
    """Check that each AI agent has been assessed against the OWASP LLM Top 10.

    The OWASP LLM Top 10 identifies the most critical security risks for
    applications using large language models. An assessment ensures that common
    attack vectors such as prompt injection, insecure output handling, and
    training data poisoning are actively mitigated.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in compliance_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.compliance.owasp_llm_top10_assessed:
                report.status = "FAIL"
                report.status_extended = f"Agent {agent.name} has not been assessed against the OWASP LLM Top 10."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has been assessed against the OWASP LLM Top 10 "
                    f"with documented mitigations."
                )
            findings.append(report)
        return findings
