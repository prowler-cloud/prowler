from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.node.node_client import node_client


class node_vpc_attached(Check):
    """Check if E2E Networks nodes are attached to a VPC."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for node in node_client.nodes:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = f"Node {node.name} is attached to a VPC."
            if not node.is_vpc_attached:
                report.status = "FAIL"
                report.status_extended = f"Node {node.name} is not attached to a VPC."
            findings.append(report)
        return findings
