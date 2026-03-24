"""ASPM-011: AI agent must use OIDC/Workload Identity instead of static credentials."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_oidc_workload_identity(Check):
    """Check that each AI agent uses OIDC/Workload Identity Federation rather than static keys.

    Agents that use static long-lived credentials while OIDC is available
    carry unnecessary long-term secret exposure risk.  The check fails when
    the agent uses static credentials AND does not use OIDC.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.identity.uses_static_credentials and not agent.identity.uses_oidc:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} uses static long-lived credentials "
                    "— OIDC/Workload Identity Federation is not configured."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} uses OIDC/Workload Identity Federation "
                    "instead of static credentials."
                )
            findings.append(report)
        return findings
