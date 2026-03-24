"""ASPM-061: AI agent must have runtime security monitoring enabled."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.runtime.runtime_client import runtime_client


class aspm_agent_runtime_monitoring_enabled(Check):
    """Check that AI agent containers have runtime security monitoring enabled.

    Without runtime monitoring tools such as Falco or Sysdig, suspicious
    system calls, unexpected privilege escalation, and anomalous file access
    go undetected until after a breach has occurred.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in runtime_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.runtime.has_runtime_monitoring:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} has no runtime monitoring — "
                    "suspicious syscalls and privilege escalation go undetected."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} has runtime security monitoring "
                    "(Falco/Sysdig) enabled."
                )
            findings.append(report)
        return findings
