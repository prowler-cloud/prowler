"""ASPM-046: AI agent must validate webhook signatures and origin on all incoming callbacks."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.network.network_client import network_client


class aspm_agent_webhook_validation(Check):
    """Check that each AI agent validates webhook signatures and origin.

    An agent is considered compliant when ``validates_webhooks`` is True.
    Accepting webhooks without signature validation allows attackers to forge
    callbacks, trigger agent actions, or replay captured payloads.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in network_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.network.validates_webhooks:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} accepts webhooks without signature validation — "
                    "replay/forgery attack risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} validates webhook signatures and origin "
                    "on all incoming callbacks."
                )
            findings.append(report)
        return findings
