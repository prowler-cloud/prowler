"""ASPM-094: Third-party vendors used by AI agent must be security-assessed."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.compliance.compliance_client import (
    compliance_client,
)


class aspm_agent_third_party_vendors_assessed(Check):
    """Check that third-party vendors used by each AI agent have been security-assessed.

    AI agents commonly rely on third-party LLM APIs, tool providers, and data
    processors. Each dependency introduces supply-chain risk. Security assessments
    (SOC 2 Type II, ISO 27001 certification, or equivalent) validate that vendors
    maintain appropriate security controls and reduce the risk of a supply-chain
    compromise propagating to the agent.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in compliance_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.compliance.third_party_vendors_assessed:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} uses third-party services without security "
                    f"assessment — supply chain risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} third-party vendors have been security-assessed "
                    f"(SOC 2, ISO 27001)."
                )
            findings.append(report)
        return findings
