from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.node.nodes_client import nodes_client


class node_rescue_mode_disabled(Check):
    """Check if E2E Cloud nodes do not have rescue mode enabled."""

    def execute(self) -> list[CheckReportE2e]:
        findings = []
        for node in nodes_client.nodes:
            report = CheckReportE2e(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = (
                f"Node {node.name} does not have rescue mode enabled."
            )
            if node.rescue_mode_status != "Disabled":
                report.status = "FAIL"
                report.status_extended = f"Node {node.name} has rescue mode enabled."
            findings.append(report)
        return findings
