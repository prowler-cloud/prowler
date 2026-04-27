"""ASPM-060: AI agent container image must be scanned for vulnerabilities before deployment."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.runtime.runtime_client import runtime_client


class aspm_agent_container_image_scanned(Check):
    """Check that AI agent container images are scanned for CVEs before deployment.

    Deploying an unscanned image means known vulnerabilities (CVEs) may be
    running in production.  Image scanning should be integrated as a CI/CD
    gate and repeated on a scheduled basis after deployment.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in runtime_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.runtime.image_scanned_for_cves:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} container image has not been scanned — "
                    "known CVEs may be present."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} container image has been scanned for "
                    "vulnerabilities before deployment."
                )
            findings.append(report)
        return findings
