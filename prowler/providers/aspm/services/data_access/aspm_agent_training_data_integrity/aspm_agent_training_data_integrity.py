"""ASPM-050: AI agent training data sources must have integrity verification."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.data_access.data_access_client import (
    data_access_client,
)


class aspm_agent_training_data_integrity(Check):
    """Check that training data sources are validated with integrity checks.

    Without integrity verification, adversaries can poison training data
    to introduce backdoors or biases into the model's behaviour.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in data_access_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.data_access.training_data_integrity_verified:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} training data has no integrity verification "
                    "— data poisoning attack risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Agent {agent.name} training data sources are validated with integrity checks."
            findings.append(report)
        return findings
