"""ASPM-098: AI agent must not be able to access data that enables downstream compromise."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.attack_paths.attack_paths_client import (
    attack_paths_client,
)


class aspm_agent_data_access_no_downstream_compromise(Check):
    """Check that AI agent-accessible data does not contain credentials or social-engineering material.

    When an agent can read data stores containing credentials (database
    connection strings, API keys, internal tokens) or material that can be
    used for social engineering (employee PII, org-chart details, internal
    process documentation), an attacker who manipulates the agent's reasoning
    can harvest that material and use it to compromise downstream systems or
    humans — completely outside the agent's declared scope.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in attack_paths_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.attack_paths.sensitive_data_enables_downstream_compromise:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} can access data containing credentials or "
                    "social-engineering material enabling downstream compromise."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} accessible data does not contain credentials "
                    "or social-engineering material."
                )
            findings.append(report)
        return findings
