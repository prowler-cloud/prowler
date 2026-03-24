"""ASPM-067: AI agent must use platform-native security controls."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.runtime.runtime_client import runtime_client


class aspm_agent_platform_security_controls(Check):
    """Check that AI agents use platform-native security controls.

    Cloud and container platforms provide built-in security controls such as
    Kubernetes Pod Security Standards, GKE Binary Authorization, and AWS
    ECS task security profiles.  Agents that do not leverage these controls
    miss a layer of defence that is already available with no additional cost.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in runtime_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.runtime.uses_platform_security_controls:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not use platform-native security "
                    "controls — additional hardening available."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} uses platform-native security controls "
                    "(Pod Security Standards, Binary Authorization)."
                )
            findings.append(report)
        return findings
