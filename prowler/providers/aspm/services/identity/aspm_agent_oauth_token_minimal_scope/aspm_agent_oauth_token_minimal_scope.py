"""ASPM-005: AI agent OAuth tokens must request minimal required scopes."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.identity.identity_client import identity_client


class aspm_agent_oauth_token_minimal_scope(Check):
    """Check that each AI agent requests OAuth tokens with the minimum required scopes.

    Overly broad OAuth scopes grant agents access to resources beyond their
    declared operational purpose, violating the principle of least privilege
    and amplifying the blast radius of a compromise.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in identity_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.identity.oauth_scope_minimal:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} OAuth tokens may have excessive scopes "
                    "or are not validated before use."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} OAuth tokens are requested with "
                    "minimal required scopes."
                )
            findings.append(report)
        return findings
