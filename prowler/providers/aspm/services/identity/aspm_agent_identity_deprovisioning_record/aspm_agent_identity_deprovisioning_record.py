"""ASPM-008: AI agent identity must have a documented deprovisioning record."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_identity_deprovisioning_record(Check):
    """Check that each AI agent has a deprovisioning record or standard operating procedure.

    Without a deprovisioning record, agent identities and the cloud permissions
    they carry persist indefinitely after the agent is retired, creating
    orphaned identities that expand the attack surface.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.identity.has_deprovisioning_record:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} lacks a deprovisioning record "
                    "— orphaned identity risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has a documented deprovisioning record."
                )
            findings.append(report)
        return findings
