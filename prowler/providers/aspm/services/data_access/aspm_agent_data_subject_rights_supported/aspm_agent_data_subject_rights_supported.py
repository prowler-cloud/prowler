"""ASPM-057: AI agents must support data subject rights (GDPR/CCPA)."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_data_subject_rights_supported(Check):
    """Check that the agent system supports data subject rights.

    GDPR and CCPA require organisations to support data subject access
    requests, portability, and the right to erasure.  Agent systems that
    store or process personal data must implement these capabilities.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.data_access.supports_data_subject_rights:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not support data subject rights "
                    "— GDPR/CCPA compliance risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} supports data subject rights (access, portability, deletion)."
            findings.append(report)
        return findings
