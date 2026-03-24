"""ASPM-003: AI agent identity must be consistently registered across all target clouds."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_identity_cross_cloud_registered(Check):
    """Check that each multi-cloud agent has a consistent identity in all target clouds.

    Multi-cloud agents that lack OIDC federation records or cross-cloud
    identity registrations may resort to static credentials, widening the
    attack surface across cloud boundaries.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.identity.cross_cloud_registered:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} lacks cross-cloud identity registration "
                    "or OIDC federation records."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has consistent identity registrations "
                    "across all target cloud providers."
                )
            findings.append(report)
        return findings
