from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.node.node_client import node_client


class node_rescue_mode_disabled(Check):
    """Check if E2E Networks nodes do not have rescue mode enabled."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for node in node_client.nodes:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = (
                f"Node {node.name} does not have rescue mode enabled."
            )
            if node.rescue_mode_status != "Disabled":
                report.status = "FAIL"
                report.status_extended = f"Node {node.name} has rescue mode enabled."
            findings.append(report)
        return findings
