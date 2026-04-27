"""ASPM-055: AI agent models must have a documented model card."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_model_has_model_card(Check):
    """Check that the agent's model has a documented model card.

    A model card documents training data, intended use, limitations, and
    bias information.  Without it, the model's provenance and risk profile
    are unknown, making responsible AI governance impossible.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.data_access.has_model_card:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} uses a model without a model card "
                    "— training data provenance is unknown."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} model has a documented model card with training data and bias information."
            findings.append(report)
        return findings
