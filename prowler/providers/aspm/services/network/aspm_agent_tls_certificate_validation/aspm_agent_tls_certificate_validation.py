"""ASPM-043: AI agent must fully validate TLS certificates on all HTTPS calls."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.network.network_client import network_client


class aspm_agent_tls_certificate_validation(Check):
    """Check that each AI agent validates TLS certificates on all HTTPS calls.

    An agent is considered compliant when ``validates_tls_certificates`` is True.
    Skipping certificate validation (chain, hostname, or expiry checks) leaves
    the agent vulnerable to man-in-the-middle attacks.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in network_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.network.validates_tls_certificates:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not fully validate TLS certificates — "
                    "vulnerable to MITM attacks."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} validates TLS certificates "
                    "(chain, hostname, expiry) on all HTTPS calls."
                )
            findings.append(report)
        return findings
