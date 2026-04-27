"""ASPM-100: AI agent compromise blast radius must be contained — full account takeover must not be possible."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.attack_paths.attack_paths_client import (
    attack_paths_client,
)


class aspm_agent_compromise_blast_radius_contained(Check):
    """Check that compromising the agent cannot lead to full cloud account takeover.

    Blast radius refers to the maximum damage achievable if an agent is fully
    compromised.  When an agent's credential chain — through role chaining,
    permission boundaries being absent, or admin-level API access — allows an
    attacker to reach account-level administrative actions (e.g., creating new
    IAM users, disabling CloudTrail, deleting all resources), the blast radius
    is effectively unbounded.  This check verifies that such a path does not
    exist.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in attack_paths_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.attack_paths.compromise_enables_full_account_takeover:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} compromise could enable full cloud account "
                    "takeover — critical blast radius."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} compromise blast radius is contained — full "
                    "account takeover is not possible."
                )
            findings.append(report)
        return findings
