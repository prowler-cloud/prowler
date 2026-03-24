"""ASPM-085: AI agent configuration changes must be tracked and drift detected."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.observability.observability_client import (
    observability_client,
)


class aspm_agent_configuration_drift_tracked(Check):
    """Check that AI agent configuration drift from baseline is tracked.

    Without configuration drift detection, unauthorised or accidental changes
    to agent configuration may go undetected, potentially weakening security
    controls or enabling privilege escalation.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in observability_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.observability.configuration_drift_tracked:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} configuration drift is not tracked — "
                    "unauthorised changes may go undetected."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} configuration changes are tracked and "
                    "drift from baseline is detected."
                )
            findings.append(report)
        return findings
