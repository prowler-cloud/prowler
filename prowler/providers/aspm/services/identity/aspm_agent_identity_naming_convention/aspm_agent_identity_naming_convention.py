"""ASPM-002: AI agent identity must follow organisational naming conventions."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_identity_naming_convention(Check):
    """Check that each AI agent identity name is compliant with naming conventions.

    Consistent naming enables automated discovery, policy scoping, and
    reduces the risk of mistaken access grants.  The ``naming_compliant``
    field is evaluated by the manifest author or a dedicated linting tool
    before ingestion.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.identity.naming_compliant:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not follow the naming convention "
                    "— non-compliant identity name detected."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} follows the organisational naming convention."
                )
            findings.append(report)
        return findings
