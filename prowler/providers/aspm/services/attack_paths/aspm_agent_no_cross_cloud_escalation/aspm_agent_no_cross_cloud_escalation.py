"""ASPM-096: AI agent must not have a cross-cloud identity chain enabling privilege escalation."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.attack_paths.attack_paths_client import (
    attack_paths_client,
)


class aspm_agent_no_cross_cloud_escalation(Check):
    """Check that AI agents cannot chain identities across cloud providers to escalate privileges.

    Cross-cloud identity chaining occurs when an agent's identity in one cloud
    can be used to assume a more privileged role in another cloud (e.g., an AWS
    IAM role trusted by a GCP service account that has broader permissions).
    This creates an attack path that bypasses the least-privilege controls of
    either cloud in isolation.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in attack_paths_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.attack_paths.cross_cloud_escalation_possible:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} can chain identities across cloud providers "
                    "to escalate privileges."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has no cross-cloud identity chain enabling "
                    "lateral privilege escalation."
                )
            findings.append(report)
        return findings
