from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.node.node_client import node_client


class node_accidental_protection_enabled(Check):
    """Check if E2E Networks nodes have accidental protection enabled."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for node in node_client.nodes:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = (
                f"Node {node.name} has accidental protection enabled."
            )
            if not node.is_accidental_protection:
                report.status = "FAIL"
                report.status_extended = (
                    f"Node {node.name} does not have accidental protection enabled."
                )
            findings.append(report)
        return findings
