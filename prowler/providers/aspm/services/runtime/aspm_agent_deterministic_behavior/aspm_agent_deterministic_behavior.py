"""ASPM-065: AI agent must produce deterministic, reproducible behaviour for audit."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.runtime.runtime_client import runtime_client


class aspm_agent_deterministic_behavior(Check):
    """Check that AI agent behaviour is deterministic and reproducible.

    Non-deterministic agents cannot be reliably audited, replayed for
    incident investigation, or compared against a known-good baseline.
    Determinism requires fixed random seeds, version-pinned models,
    and idempotent tool implementations.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in runtime_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.runtime.behavior_deterministic:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} behaviour is non-deterministic — "
                    "cannot audit or replay agent actions."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} produces deterministic, reproducible "
                    "behaviour for audit."
                )
            findings.append(report)
        return findings
