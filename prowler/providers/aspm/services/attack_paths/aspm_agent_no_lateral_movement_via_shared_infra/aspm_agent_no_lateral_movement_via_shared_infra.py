"""ASPM-099: AI agent must not be able to access shared infrastructure used by sibling agents."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.attack_paths.attack_paths_client import (
    attack_paths_client,
)


class aspm_agent_no_lateral_movement_via_shared_infra(Check):
    """Check that AI agents cannot access sibling agent infrastructure or shared credential stores.

    When multiple agents share infrastructure components — message queues,
    databases, secret stores, shared file systems, or configuration services —
    compromise of one agent can be used as a pivot to attack adjacent agents.
    This lateral movement path is especially dangerous in multi-agent
    orchestration systems where agent-to-agent trust is implicit.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in attack_paths_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.attack_paths.lateral_movement_via_shared_infra:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} can access shared infrastructure used by "
                    "sibling agents — lateral movement risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} cannot access sibling agent infrastructure "
                    "or shared credential stores."
                )
            findings.append(report)
        return findings
