from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.node.node_client import node_client


class node_encryption_enabled(Check):
    """Check if E2E Networks nodes have encryption enabled."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for node in node_client.nodes:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = f"Node {node.name} has encryption enabled."
            if not node.is_encryption_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Node {node.name} does not have encryption enabled."
                )
            findings.append(report)
        return findings
