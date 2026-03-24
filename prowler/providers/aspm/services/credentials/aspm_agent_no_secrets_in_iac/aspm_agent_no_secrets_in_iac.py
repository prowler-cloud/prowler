"""ASPM-031: AI agent IaC templates must not embed secrets."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.credentials.credentials_client import (
    credentials_client,
)


class aspm_agent_no_secrets_in_iac(Check):
    """Check that each AI agent has no secrets embedded in Terraform or CloudFormation.

    Secrets in IaC templates are stored in state files, shared with the entire
    IaC team, and often pushed to source control.  They should be replaced with
    dynamic references to a secrets manager.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in credentials_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if agent.credentials.secrets_in_iac:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has secrets embedded in IaC "
                    "— these should be replaced with secrets manager references."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has no secrets embedded in Terraform or "
                    "CloudFormation templates."
                )
            findings.append(report)
        return findings
