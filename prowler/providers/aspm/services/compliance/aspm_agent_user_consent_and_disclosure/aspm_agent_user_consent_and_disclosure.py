"""ASPM-095: AI agent must disclose its actions to users and obtain appropriate consent."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.compliance.compliance_client import (
    compliance_client,
)


class aspm_agent_user_consent_and_disclosure(Check):
    """Check that each AI agent discloses its actions and obtains user consent.

    Agents acting autonomously on behalf of users must inform those users about
    what actions will be taken and obtain meaningful consent where required.
    Failure to disclose agent behaviour and obtain consent violates privacy
    regulations (GDPR, CCPA), ethics guidelines, and sector-specific rules,
    and erodes user trust in AI systems.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in compliance_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.compliance.user_consent_and_disclosure:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} acts on behalf of users without disclosure or "
                    f"consent — ethics and regulatory risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} discloses its actions to users and obtains "
                    f"appropriate consent."
                )
            findings.append(report)
        return findings
