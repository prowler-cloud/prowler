"""ASPM-090: AI agent must have a documented access control policy that is enforced and audited."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.compliance.compliance_client import (
    compliance_client,
)


class aspm_agent_access_control_policy_enforced(Check):
    """Check that each AI agent has an enforced and audited access control policy.

    Access control policies define who or what may interact with an agent, what
    actions are permitted, and under which conditions. Without enforcement and
    audit trails, unauthorised access to agent capabilities or the data it
    processes can go undetected.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in compliance_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.compliance.access_control_policy_enforced:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} lacks an enforced access control policy — "
                    f"governance controls are absent."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has a documented access control policy that "
                    f"is enforced and audited."
                )
            findings.append(report)
        return findings
