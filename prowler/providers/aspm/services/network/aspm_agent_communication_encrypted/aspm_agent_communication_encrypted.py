"""ASPM-037: AI agent communication must be encrypted with TLS and mTLS."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.network.network_client import network_client


class aspm_agent_communication_encrypted(Check):
    """Check that each AI agent uses HTTPS-only communication with mTLS enforced.

    An agent is considered compliant when both ``uses_https_only`` and
    ``mtls_enforced`` are True.  Unencrypted or partially encrypted communication
    exposes agent traffic to interception and tampering.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in network_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.network.uses_https_only and not agent.network.mtls_enforced:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not use HTTPS-only communication "
                    "and mTLS is not enforced in the service mesh."
                )
            elif not agent.network.uses_https_only:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not use HTTPS-only communication — "
                    "plaintext traffic may be exposed."
                )
            elif not agent.network.mtls_enforced:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} does not enforce mTLS in the service mesh — "
                    "peer identity cannot be verified."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} uses TLS for all communication "
                    "with mTLS enforced in the service mesh."
                )
            findings.append(report)
        return findings
