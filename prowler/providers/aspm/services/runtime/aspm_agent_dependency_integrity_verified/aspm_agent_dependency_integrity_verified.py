"""ASPM-066: AI agent runtime dependencies must be verified via checksums or signatures."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.runtime.runtime_client import runtime_client


class aspm_agent_dependency_integrity_verified(Check):
    """Check that AI agent runtime dependencies are verified with checksums or signatures.

    Downloading dependencies without integrity verification opens the agent to
    supply chain attacks where a package registry is compromised and a malicious
    version is substituted.  Verification must happen at install time and can be
    enforced via lock files with hashes, Sigstore, or in-toto attestations.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in runtime_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.runtime.dependencies_integrity_checked:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} downloads dependencies without "
                    "integrity verification — supply chain attack risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} runtime dependencies are verified "
                    "via checksums/signatures."
                )
            findings.append(report)
        return findings
