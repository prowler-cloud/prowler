"""ASPM-056: AI agent outputs must be validated and redacted for sensitive data."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_output_validated(Check):
    """Check that agent outputs are validated and redacted for sensitive data.

    Agent outputs may inadvertently include PII, credentials, or other
    sensitive data from the LLM context.  Validation and redaction must
    occur before delivering outputs to end users or downstream systems.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.data_access.output_validated_for_sensitive_data:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} outputs are not validated "
                    "— PII or sensitive data may be leaked in responses."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} outputs are validated and redacted for sensitive data before delivery."
            findings.append(report)
        return findings
