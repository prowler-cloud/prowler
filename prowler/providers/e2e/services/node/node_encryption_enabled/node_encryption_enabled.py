from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.node.nodes_client import nodes_client


class node_encryption_enabled(Check):
    """Check if E2E Cloud nodes have encryption enabled."""

    def execute(self) -> list[CheckReportE2e]:
        findings = []
        for node in nodes_client.nodes:
            report = CheckReportE2e(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = f"Node {node.name} has encryption enabled."
            if not node.is_encryption_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Node {node.name} does not have encryption enabled."
                )
            findings.append(report)
        return findings
