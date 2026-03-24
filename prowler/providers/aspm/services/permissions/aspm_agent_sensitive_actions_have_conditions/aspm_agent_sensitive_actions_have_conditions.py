"""ASPM-019: High-risk agent permissions must be protected by IAM conditions."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.permissions.permissions_client import (
    permissions_client,
)


class aspm_agent_sensitive_actions_have_conditions(Check):
    """Check that agent sensitive permissions are guarded by IAM conditions.

    High-risk permissions such as ``kms:Decrypt``, ``secretsmanager:GetSecretValue``,
    or ``sts:AssumeRole`` without accompanying conditions (e.g. source IP, tag
    match, time-of-day) can be exercised from any context.  IAM conditions
    provide defence-in-depth by constraining when and how these permissions apply.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in permissions_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.permissions.has_condition_on_sensitive_actions:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has high-risk permissions "
                    "(KMS, Secrets Manager) without conditions."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} sensitive permissions are protected "
                    "by conditions (IP, tag, time)."
                )
            findings.append(report)
        return findings
