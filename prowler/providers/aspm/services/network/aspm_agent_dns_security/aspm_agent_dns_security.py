"""ASPM-045: AI agent must use DNSSEC/DoH/DoT for secure DNS resolution."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.network.network_client import network_client


class aspm_agent_dns_security(Check):
    """Check that each AI agent uses DNSSEC, DNS-over-HTTPS, or DNS-over-TLS.

    An agent is considered compliant when ``uses_dnssec`` is True.
    Standard plaintext DNS lookups are vulnerable to spoofing and hijacking,
    which can redirect agent traffic to attacker-controlled endpoints.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in network_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.network.uses_dnssec:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not use secure DNS — "
                    "vulnerable to DNS spoofing and hijacking."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} uses DNSSEC/DoH/DoT for secure DNS resolution."
                )
            findings.append(report)
        return findings
