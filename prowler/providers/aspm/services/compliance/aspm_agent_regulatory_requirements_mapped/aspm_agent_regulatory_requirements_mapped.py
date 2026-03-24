"""ASPM-092: AI agent must have all applicable regulatory requirements mapped."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.compliance.compliance_client import (
    compliance_client,
)


class aspm_agent_regulatory_requirements_mapped(Check):
    """Check that each AI agent has applicable regulatory requirements mapped.

    AI agents operating in regulated industries must identify and map all
    applicable regulatory requirements (e.g. HIPAA for healthcare, PCI-DSS for
    payment processing, SOX for financial reporting). Without this mapping,
    compliance gaps may remain undetected until an audit or incident exposes them.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in compliance_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.compliance.regulatory_requirements_mapped:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} lacks regulatory requirement mapping — "
                    f"compliance gaps may exist."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has all applicable regulatory requirements "
                    f"(HIPAA, PCI-DSS, etc.) mapped."
                )
            findings.append(report)
        return findings
