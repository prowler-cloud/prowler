from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.node.node_client import node_client


class node_public_ip_not_assigned(Check):
    """Check if E2E Networks nodes do not have a public IP assigned."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for node in node_client.nodes:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = f"Node {node.name} does not have a public IP."
            if node.has_public_ip:
                report.status = "FAIL"
                report.status_extended = f"Node {node.name} has a public IP assigned."
            findings.append(report)
        return findings
